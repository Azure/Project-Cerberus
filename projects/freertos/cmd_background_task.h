// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_BACKGROUND_TASK_H_
#define CMD_BACKGROUND_TASK_H_

#include "FreeRTOS.h"
#include "semphr.h"
#include "attestation/attestation_slave.h"
#include "cmd_interface/cmd_background.h"
#include "cmd_interface/config_reset.h"
#include "crypto/hash.h"
#include "riot/riot_key_manager.h"


/**
 * The task context for executing attestation requests.
 */
struct cmd_background_attestation {
	struct attestation_slave *attestation;			/**< Attestation manager to utilize for attestation operations. */
	struct hash_engine *hash;						/**< Hash engine to be used in attestation operations. */
	int attestation_status;							/**< The attestation operation status. */
	uint8_t *unseal_request;						/**< The current unseal request. */
	uint8_t key[AUX_ATTESTATION_KEY_256BIT];		/**< Buffer for the unsealed key. */
};

/**
 * The task context for executing configuration reset requests.
 */
struct cmd_background_config {
	struct config_reset *reset;						/**< Configuration reset manager. */
	int config_status;								/**< Status for configuration operations. */
};

/**
 * The task context for executing RIoT certificate requests.
 */
struct cmd_background_riot {
	struct riot_key_manager *keys;					/**< Manager for the RIoT keys and certificates. */
	int cert_state;									/**< Certificate authentication state. */
};

/**
 * Task for executing background operations from the command handler.
 */
struct cmd_background_task {
	struct cmd_background base;						/**< Interface to control the task. */
	TaskHandle_t task;								/**< The task that will execute requests. */
	SemaphoreHandle_t lock;							/**< Synchronization for task status. */
	uint8_t running;								/**< Flag indicating if an operation is running. */
	struct cmd_background_attestation attestation;	/**< Attestation command context. */
	struct cmd_background_config config;			/**< Configuration reset context. */
	struct cmd_background_riot riot;				/**< RIoT key context. */

	/**
	 * Internal handler that can be called before processing base events.  This allows the task to
	 * be extended to support different actions.
	 *
	 * @param task The task context for the notification.
	 * @param notification The notification value received by the task.
	 */
	void (*ext_handler) (struct cmd_background_task *task, uint32_t notification);
};


int cmd_background_task_init (struct cmd_background_task *task,
	struct attestation_slave *attestation, struct hash_engine *hash, struct config_reset *reset,
	struct riot_key_manager *riot);
int cmd_background_task_start (struct cmd_background_task *task);

/* Internal definitions for use by derived types. */
#define	CMD_BACKGROUND_EXTERNAL_HANDLER			(1U << 31)


#endif /* CMD_BACKGROUND_TASK_H_ */
