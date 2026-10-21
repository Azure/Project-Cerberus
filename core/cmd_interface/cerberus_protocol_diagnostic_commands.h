// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_PROTOCOL_DIAGNOSTIC_COMMANDS_H_
#define CERBERUS_PROTOCOL_DIAGNOSTIC_COMMANDS_H_

#include "cmd_interface/cerberus_protocol.h"
#include "cmd_interface/cmd_device.h"
#include "cmd_interface/cmd_interface.h"


#pragma pack(push, 1)
/**
 * Cerberus protocol heap statistics diagnostic request format
 */
struct cerberus_protocol_heap_stats {
	struct cerberus_protocol_header header;	/**< Message header */
};

/**
 * Cerberus protocol heap statistics diagnostic response format
 */
struct cerberus_protocol_heap_stats_response {
	struct cerberus_protocol_header header;	/**< Message header */
	struct cmd_device_heap_stats heap;		/**< Current heap statistics */
};

/**
 * Cerberus protocol stack statistics diagnostic request format
 */
struct cerberus_protocol_stack_stats {
	struct cerberus_protocol_header header;	/**< Message header */
	uint32_t task_offset;					/**< Offset of the first task to return */
};

/**
 * Cerberus protocol stack statistics diagnostic response format
 */
struct cerberus_protocol_stack_stats_response {
	struct cerberus_protocol_header header;		/**< Message header */
	struct cmd_device_stack_stats stack_stats;	/**< Current stack statistics */
};


/**
 * Get the total message length for a get stack statistics response message.
 *
 * @param len Length of the stack statistics data.
 */
#define	cerberus_protocol_get_stack_stats_response_length(len) \
	(len + sizeof (struct cerberus_protocol_stack_stats_response))

/**
 * Maximum amount of supported stack statistics data that can be returned in a single request
 *
 * @param req The command request structure containing the message.
 */
#define	CERBERUS_PROTOCOL_MAX_STACK_STATS(req) \
	(cmd_interface_msg_get_max_response (req) - sizeof (struct cerberus_protocol_stack_stats_response))

#pragma pack(pop)


int cerberus_protocol_heap_stats (const struct cmd_device *device,
	struct cmd_interface_msg *request);

int cerberus_protocol_stack_stats (const struct cmd_device *device,
	struct cmd_interface_msg *request);


#endif	/* CERBERUS_PROTOCOL_DIAGNOSTIC_COMMANDS_H_ */
