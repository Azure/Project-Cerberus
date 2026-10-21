// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "cerberus_protocol_diagnostic_commands.h"
#include "common/unused.h"


/**
 * Process request to get heap usage statistics.
 *
 * @param device Device API to use to query heap stats.
 * @param request Heap statistics request to process.
 *
 * @return 0 if request completed successfully or an error code.
 */
int cerberus_protocol_heap_stats (const struct cmd_device *device,
	struct cmd_interface_msg *request)
{
#ifdef CMD_ENABLE_HEAP_STATS
	struct cerberus_protocol_heap_stats_response *rsp =
		(struct cerberus_protocol_heap_stats_response*) request->data;

	if (request->length != sizeof (struct cerberus_protocol_heap_stats)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	request->length = sizeof (struct cerberus_protocol_heap_stats_response);

	return device->get_heap_stats (device, &rsp->heap);
#else
	UNUSED (device);
	UNUSED (request);

	return CMD_HANDLER_UNSUPPORTED_COMMAND;
#endif
}

/**
 * Process request to get stack usage statistics.
 *
 * @param device Device API to use to query stack stats.
 * @param request Stack statistics request to process.
 *
 * @return 0 if request completed successfully or an error code.
 */
int cerberus_protocol_stack_stats (const struct cmd_device *device,
	struct cmd_interface_msg *request)
{
#ifdef CMD_ENABLE_STACK_STATS
	struct cerberus_protocol_stack_stats *req =
		(struct cerberus_protocol_stack_stats*) request->data;
	struct cerberus_protocol_stack_stats_response *rsp =
		(struct cerberus_protocol_stack_stats_response*) request->data;
	size_t task_offset;
	int status;

	if (request->length != sizeof (struct cerberus_protocol_stack_stats)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	task_offset = req->task_offset;

	status = device->get_stack_stats (device, task_offset, &rsp->stack_stats,
		CERBERUS_PROTOCOL_MAX_STACK_STATS (request));
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	request->length = cerberus_protocol_get_stack_stats_response_length (status);

	return 0;
#else
	UNUSED (device);
	UNUSED (request);

	return CMD_HANDLER_UNSUPPORTED_COMMAND;
#endif
}
