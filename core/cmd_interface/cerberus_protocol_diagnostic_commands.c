// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "cerberus_protocol_diagnostic_commands.h"


/**
 * Process request to get heap usage statistics.
 *
 * @param device Device API to use to query heap stats.
 * @param request Heap statistics request to process.
 *
 * @return 0 if request completed successfully or an error code.
 */
int cerberus_protocol_heap_stats (struct cmd_device *device, struct cmd_interface_msg *request)
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
	return CMD_HANDLER_UNSUPPORTED_COMMAND;
#endif
}
