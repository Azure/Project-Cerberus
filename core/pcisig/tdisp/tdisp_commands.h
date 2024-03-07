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
#define TDISP_CURRENT_VERSION 		TDISP_VERSION_1_0

/**
 * TDISP interface context.
 */
struct tdisp_interface_context {
	struct tdisp_interface_id interface_id;	/**< TDISP Interface Id. */
};

/**
 * TDISP state.
 */
struct tdisp_state {
	struct tdisp_interface_context interface_context[TDISP_INTERFACE_MAX_COUNT];
	uint8_t interface_context_count;
};


int tdisp_init_state (struct tdisp_state *state);

void tdisp_generate_error_response (struct cmd_interface_msg *response, uint8_t version,
	uint32_t function_id, uint32_t error_code, uint32_t error_data);

int tdisp_get_version (struct tdisp_state *tdisp_state,
	const uint8_t *version_num, uint8_t version_num_count, struct cmd_interface_msg *request);


#endif /* TDISP_COMMANDS_H */