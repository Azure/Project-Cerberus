// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_SYSTEM_TESTING_H_
#define CMD_INTERFACE_SYSTEM_TESTING_H_

#include "cmd_interface/cerberus_protocol.h"


/**
 * Number of firmware version strings.
 */
#define FW_VERSION_COUNT 2

extern const char CERBERUS_FW_VERSION[CERBERUS_PROTOCOL_FW_VERSION_LEN];
extern const char RIOT_CORE_VERSION[CERBERUS_PROTOCOL_FW_VERSION_LEN];
extern const char *fw_version_list[FW_VERSION_COUNT];

extern uint8_t CMD_DEVICE_UUID[];
extern const size_t CMD_DEVICE_UUID_LEN;


#endif /* CMD_INTERFACE_SYSTEM_TESTING_H_ */
