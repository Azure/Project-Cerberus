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
	struct cerberus_protocol_header header;					/**< Message header */
};

/**
 * Cerberus protocol heap statistics diagnostic response format
 */
struct cerberus_protocol_heap_stats_response {
	struct cerberus_protocol_header header;					/**< Message header */
	struct cmd_device_heap_stats heap;						/**< Current heap statistics */
};
#pragma pack(pop)


int cerberus_protocol_heap_stats (struct cmd_device *device, struct cmd_interface_msg *request);


#endif /* CERBERUS_PROTOCOL_DIAGNOSTIC_COMMANDS_H_ */
