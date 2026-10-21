// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef TDISP_COMMANDS_H
#define TDISP_COMMANDS_H

#include "platform_config.h"


/* Configurable parameters. Defaults can be overridden in platform_config.h. */

/**
 * Maximum TDISP interface counts.
 */
#ifndef TDISP_INTERFACE_MAX_COUNT
#define TDISP_INTERFACE_MAX_COUNT	64
#endif

#define TDISP_VERSION_1_0			0x10
#define TDISP_CURRENT_VERSION		TDISP_VERSION_1_0

void tdisp_generate_error_response (struct cmd_interface_msg *response, uint8_t version,
	uint32_t function_id, uint32_t error_code, uint32_t error_data);

int tdisp_get_version (const struct tdisp_driver *tdisp_driver,	const uint8_t *version_num,
	uint8_t version_num_count, struct cmd_interface_msg *request);

int tdisp_get_capabilities (const struct tdisp_driver *tdisp_driver, const uint8_t *tdisp_messages,
	uint32_t tdisp_messages_count, struct cmd_interface_msg *request);

int tdisp_lock_interface (const struct tdisp_tdi_context_manager *tdi_context_manager,
	const struct tdisp_driver *tdisp_driver, const struct rng_engine *rng_engine,
	struct cmd_interface_msg *request);

int tdisp_get_device_interface_report (const struct tdisp_driver *tdisp_driver,
	struct cmd_interface_msg *request);

int tdisp_get_device_interface_state (const struct tdisp_driver *tdisp_driver,
	struct cmd_interface_msg *request);

int tdisp_start_interface (const struct tdisp_tdi_context_manager *tdi_context_manager,
	const struct tdisp_driver *tdisp_driver, struct cmd_interface_msg *request);

int tdisp_stop_interface (const struct tdisp_driver *tdisp_driver,
	struct cmd_interface_msg *request);


#endif	/* TDISP_COMMANDS_H */
