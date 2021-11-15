// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_PROTOCOL_DIAGNOSTIC_COMMANDS_TESTING_H_
#define CERBERUS_PROTOCOL_DIAGNOSTIC_COMMANDS_TESTING_H_

#include "testing.h"
#include "cmd_interface/cmd_interface.h"
#include "testing/mock/cmd_interface/cmd_device_mock.h"


void cerberus_protocol_diagnostic_commands_testing_process_heap_stats (CuTest *test,
	struct cmd_interface *cmd, struct cmd_device_mock *device);
void cerberus_protocol_diagnostic_commands_testing_process_heap_stats_invalid_len (CuTest *test,
	struct cmd_interface *cmd);
void cerberus_protocol_diagnostic_commands_testing_process_heap_stats_fail (CuTest *test,
	struct cmd_interface *cmd, struct cmd_device_mock *device);


#endif /* CERBERUS_PROTOCOL_DIAGNOSTIC_COMMANDS_TESTING_H_ */
