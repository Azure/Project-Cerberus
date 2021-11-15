// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_PROTOCOL_DEBUG_COMMANDS_TESTING_H_
#define CERBERUS_PROTOCOL_DEBUG_COMMANDS_TESTING_H_

#include <stdint.h>
#include <stddef.h>
#include "testing.h"
#include "cmd_interface/cmd_interface.h"
#include "cmd_interface/device_manager.h"
#include "riot/riot_key_manager.h"
#include "testing/mock/attestation/attestation_master_mock.h"
#include "testing/mock/cmd_interface/cmd_background_mock.h"
#include "testing/mock/crypto/hash_mock.h"


void cerberus_protocol_debug_commands_testing_process_debug_fill_log (CuTest *test,
	struct cmd_interface *cmd, struct cmd_background_mock *background);


#endif /* CERBERUS_PROTOCOL_DEBUG_COMMANDS_TESTING_H_ */
