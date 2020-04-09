// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_PROTOCOL_DEBUG_COMMANDS_H_
#define CERBERUS_PROTOCOL_DEBUG_COMMANDS_H_

#include "cmd_interface/cmd_background.h"
#include "cmd_interface/cmd_interface.h"
#include "cmd_interface/device_manager.h"
#include "attestation/attestation_master.h"
#include "crypto/hash.h"


/**
 * Escape sequence to intitiate transaction with slave device instead of responding to system.
 */
#define	ATTESTATION_START_TEST_ESCAPE_SEQ	0xBBCC


#pragma pack(push, 1)
/* TODO: Define command formats for all debug commands. */
#pragma pack(pop)


int cerberus_protocol_debug_fill_log (struct cmd_background *background,
	struct cmd_interface_request *request);

int cerberus_protocol_get_device_certificate (struct device_manager *device_mgr,
	struct cmd_interface_request *request);
int cerberus_protocol_get_device_cert_digest (struct device_manager *device_mgr,
	struct hash_engine *hash, struct cmd_interface_request *request);

int cerberus_protocol_get_device_challenge (struct device_manager *device_mgr,
	struct attestation_master *attestation, struct hash_engine *hash,
	struct cmd_interface_request *request);

int cerberus_protocol_start_attestation (struct cmd_interface_request *request);
int cerberus_protocol_get_attestation_state (struct device_manager *device_mgr,
	struct cmd_interface_request *request);


#endif /* CERBERUS_PROTOCOL_DEBUG_COMMANDS_H_ */
