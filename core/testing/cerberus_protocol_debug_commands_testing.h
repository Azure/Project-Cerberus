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
#include "mock/cmd_background_mock.h"
#include "mock/attestation_master_mock.h"
#include "mock/hash_mock.h"


void cerberus_protocol_debug_commands_testing_process_debug_fill_log (CuTest *test,
	struct cmd_interface *cmd, struct cmd_background_mock *background);

void cerberus_protocol_debug_commands_testing_process_get_device_certificate (CuTest *test,
	struct cmd_interface *cmd, struct device_manager *device_manager);
void cerberus_protocol_debug_commands_testing_process_get_device_certificate_invalid_len (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_debug_commands_testing_process_get_device_certificate_invalid_cert_num (
	CuTest *test, struct cmd_interface *cmd, struct device_manager *device_manager);
void cerberus_protocol_debug_commands_testing_process_get_device_certificate_get_chain_fail (
	CuTest *test, struct cmd_interface *cmd);

void cerberus_protocol_debug_commands_testing_process_get_device_cert_digest (CuTest *test,
	struct cmd_interface *cmd, struct hash_engine_mock *hash,
	struct device_manager *device_manager);
void cerberus_protocol_debug_commands_testing_process_get_device_cert_digest_invalid_len (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_debug_commands_testing_process_get_device_cert_digest_invalid_cert_num (
	CuTest *test, struct cmd_interface *cmd, struct device_manager *device_manager);
void cerberus_protocol_debug_commands_testing_process_get_device_cert_digest_get_chain_fail (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_debug_commands_testing_process_get_device_cert_digest_hash_fail (
	CuTest *test, struct cmd_interface *cmd, struct hash_engine_mock *hash,
	struct device_manager *device_manager);

void cerberus_protocol_debug_commands_testing_process_get_device_challenge (CuTest *test,
	struct cmd_interface *cmd, struct riot_key_manager *riot, struct hash_engine_mock *hash,
	struct attestation_master_mock *master_attestation, struct device_manager *device_manager);
void cerberus_protocol_debug_commands_testing_process_get_device_challenge_invalid_len (
	CuTest *test, struct cmd_interface *cmd);


#endif /* CERBERUS_PROTOCOL_DEBUG_COMMANDS_TESTING_H_ */
