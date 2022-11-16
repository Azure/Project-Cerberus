// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_CMD_HANDLER_PFM_H_
#define MANIFEST_CMD_HANDLER_PFM_H_

#include "manifest/manifest_cmd_handler.h"
#include "host_fw/host_processor.h"
#include "host_fw/host_state_manager.h"
#include "spi_filter/spi_filter_interface.h"


/**
 * A handler for executing requests for a single PFM.
 */
struct manifest_cmd_handler_pfm {
	struct manifest_cmd_handler base;		/**< Base manifest handler. */
	struct host_processor *host;			/**< Host instance for the PFM. */
	struct host_state_manager *host_state;	/**< Manager for host state information. */
	struct hash_engine *hash;				/**< Hash engine for run-time verification. */
	struct rsa_engine *rsa;					/**< RSA engine for run-time verification. */
	struct spi_filter_interface *filter;	/**< SPI filter for the host. */
};


int manifest_cmd_handler_pfm_init (struct manifest_cmd_handler_pfm *handler,
	struct manifest_cmd_handler_state *state, const struct manifest_manager *manifest,
	const struct event_task *task, struct host_processor *host,
	struct host_state_manager *host_state, struct hash_engine *hash, struct rsa_engine *rsa,
	struct spi_filter_interface *filter);
int manifest_cmd_handler_pfm_init_state (const struct manifest_cmd_handler_pfm *handler);
void manifest_cmd_handler_pfm_release (const struct manifest_cmd_handler_pfm *handler);


#endif /* MANIFEST_CMD_HANDLER_PFM_H_ */
