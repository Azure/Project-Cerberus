// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_PROTOCOL_REQUIRED_COMMANDS_TESTING_H_
#define CERBERUS_PROTOCOL_REQUIRED_COMMANDS_TESTING_H_

#include <stdint.h>
#include <stddef.h>
#include "testing.h"
#include "cmd_interface/cmd_interface.h"
#include "cmd_interface/device_manager.h"
#include "riot/riot_key_manager.h"
#include "testing/mock/attestation/attestation_slave_mock.h"
#include "testing/mock/cmd_interface/cmd_background_mock.h"
#include "testing/mock/cmd_interface/cmd_device_mock.h"
#include "testing/mock/cmd_interface/session_manager_mock.h"
#include "testing/mock/keystore/keystore_mock.h"


void cerberus_protocol_required_commands_testing_supports_all_required_commands (CuTest *test,
	struct cmd_interface *cmd, const char *version,
	struct attestation_slave_mock *slave_attestation, struct device_manager *device_manager,
	struct cmd_background_mock *background, struct keystore_mock *keystore,
	struct cmd_device_mock *cmd_device, const uint8_t* csr, size_t csr_length, uint16_t vendor_id,
	uint16_t device_id, uint16_t subsystem_vid, uint16_t subsystem_id,
	struct session_manager_mock *session);

void cerberus_protocol_required_commands_testing_process_get_fw_version (CuTest *test,
	struct cmd_interface *cmd, const char *version);
void cerberus_protocol_required_commands_testing_process_get_fw_version_riot (CuTest *test,
	struct cmd_interface *cmd, const char *version);
void cerberus_protocol_required_commands_testing_process_get_fw_version_unset_version (CuTest *test,
	struct cmd_interface *cmd);
void cerberus_protocol_required_commands_testing_process_get_fw_version_invalid_len (CuTest *test,
	struct cmd_interface *cmd);
void cerberus_protocol_required_commands_testing_process_get_fw_version_unsupported_area (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_required_commands_testing_process_get_fw_version_bad_count (CuTest *test,
	struct cmd_interface *cmd);

void cerberus_protocol_required_commands_testing_process_get_certificate_digest (CuTest *test,
	struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation,
	struct session_manager_mock *session);
void cerberus_protocol_required_commands_testing_process_get_certificate_digest_no_key_exchange (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation);
void cerberus_protocol_required_commands_testing_process_get_certificate_digest_in_session (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation);
void cerberus_protocol_required_commands_testing_process_get_certificate_digest_aux_slot (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation);
void cerberus_protocol_required_commands_testing_process_get_certificate_digest_limited_response (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation);
void cerberus_protocol_required_commands_testing_process_get_certificate_digest_unsupported_slot (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation);
void cerberus_protocol_required_commands_testing_process_get_certificate_digest_unavailable_cert (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation);
void cerberus_protocol_required_commands_testing_process_get_certificate_digest_encryption_unsupported (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_required_commands_testing_process_get_certificate_digest_invalid_len (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_required_commands_testing_process_get_certificate_digest_unsupported_algo (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_required_commands_testing_process_get_certificate_digest_invalid_slot (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_required_commands_testing_process_get_certificate_digest_fail (CuTest *test,
	struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation);

void cerberus_protocol_required_commands_testing_process_get_certificate (CuTest *test,
	struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation);
void cerberus_protocol_required_commands_testing_process_get_certificate_length_0 (CuTest *test,
	struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation);
void cerberus_protocol_required_commands_testing_process_get_certificate_aux_slot (CuTest *test,
	struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation);
void cerberus_protocol_required_commands_testing_process_get_certificate_limited_response (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation);
void cerberus_protocol_required_commands_testing_process_get_certificate_invalid_offset (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation);
void cerberus_protocol_required_commands_testing_process_get_certificate_valid_offset_and_length_beyond_cert_len (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation);
void cerberus_protocol_required_commands_testing_process_get_certificate_length_too_big (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation);
void cerberus_protocol_required_commands_testing_process_get_certificate_unsupported_slot (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation);
void cerberus_protocol_required_commands_testing_process_get_certificate_unsupported_cert (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation);
void cerberus_protocol_required_commands_testing_process_get_certificate_unavailable_cert (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation);
void cerberus_protocol_required_commands_testing_process_get_certificate_invalid_len (CuTest *test,
	struct cmd_interface *cmd);
void cerberus_protocol_required_commands_testing_process_get_certificate_invalid_slot_num (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_required_commands_testing_process_get_certificate_fail (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation);

void cerberus_protocol_required_commands_testing_process_get_challenge_response (CuTest *test,
	struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation,
	struct session_manager_mock *session);
void cerberus_protocol_required_commands_testing_process_get_challenge_response_no_session_mgr (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation);
void cerberus_protocol_required_commands_testing_process_get_challenge_response_key_exchange_not_requested (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation);
void cerberus_protocol_required_commands_testing_process_get_challenge_response_limited_response (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation,
	struct session_manager_mock *session);
void cerberus_protocol_required_commands_testing_process_get_challenge_response_limited_response_no_session_mgr (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation);
void cerberus_protocol_required_commands_testing_process_get_challenge_response_limited_response_key_exchange_not_requested (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation);
void cerberus_protocol_required_commands_testing_process_get_challenge_response_fail (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation);
void cerberus_protocol_required_commands_testing_process_get_challenge_response_invalid_len (
	CuTest *test, struct cmd_interface *cmd);

void cerberus_protocol_required_commands_testing_process_get_capabilities (CuTest *test,
	struct cmd_interface *cmd, struct device_manager *device_manager);
void cerberus_protocol_required_commands_testing_process_get_capabilities_invalid_device (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_required_commands_testing_process_get_capabilities_invalid_len (CuTest *test,
	struct cmd_interface *cmd);

void cerberus_protocol_required_commands_testing_process_get_devid_csr (CuTest *test,
	struct cmd_interface *cmd, const uint8_t* csr, size_t csr_length);
void cerberus_protocol_required_commands_testing_process_get_devid_csr_invalid_len (CuTest *test,
	struct cmd_interface *cmd);
void cerberus_protocol_required_commands_testing_process_get_devid_csr_unsupported_index (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_required_commands_testing_process_get_devid_csr_too_big (CuTest *test,
	struct cmd_interface *cmd, struct riot_key_manager *riot);
void cerberus_protocol_required_commands_testing_process_get_devid_csr_too_big_limited_response (
	CuTest *test, struct cmd_interface *cmd, const uint8_t* csr, size_t csr_length);

void cerberus_protocol_required_commands_testing_process_import_signed_dev_id_cert (CuTest *test,
	struct cmd_interface *cmd, struct keystore_mock *keystore,
	struct cmd_background_mock *background);
void cerberus_protocol_required_commands_testing_process_import_root_ca_cert (CuTest *test,
	struct cmd_interface *cmd, struct keystore_mock *keystore,
	struct cmd_background_mock *background);
void cerberus_protocol_required_commands_testing_process_import_intermediate_cert (CuTest *test,
	struct cmd_interface *cmd, struct keystore_mock *keystore,
	struct cmd_background_mock *background);
void cerberus_protocol_required_commands_testing_process_import_signed_ca_cert_invalid_len (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_required_commands_testing_process_import_signed_ca_cert_no_cert (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_required_commands_testing_process_import_signed_ca_cert_bad_cert_length (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_required_commands_testing_process_import_signed_ca_cert_unsupported_index (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_required_commands_testing_process_import_signed_dev_id_cert_save_error (
	CuTest *test, struct cmd_interface *cmd, struct keystore_mock *keystore);
void cerberus_protocol_required_commands_testing_process_import_root_ca_cert_save_error (
	CuTest *test, struct cmd_interface *cmd, struct keystore_mock *keystore);
void cerberus_protocol_required_commands_testing_process_import_intermediate_cert_save_error (
	CuTest *test, struct cmd_interface *cmd, struct keystore_mock *keystore);
void cerberus_protocol_required_commands_testing_process_import_signed_ca_cert_authenticate_error (
	CuTest *test, struct cmd_interface *cmd, struct keystore_mock *keystore,
	struct cmd_background_mock *background);

void cerberus_protocol_required_commands_testing_process_get_signed_cert_state (CuTest *test,
	struct cmd_interface *cmd, struct cmd_background_mock *background);
void cerberus_protocol_required_commands_testing_process_get_signed_cert_state_invalid_len (
	CuTest *test, struct cmd_interface *cmd);

void cerberus_protocol_required_commands_testing_process_get_device_info (CuTest *test,
	struct cmd_interface *cmd, struct cmd_device_mock *cmd_device);
void cerberus_protocol_required_commands_testing_process_get_device_info_limited_response (
	CuTest *test, struct cmd_interface *cmd, struct cmd_device_mock *cmd_device);
void cerberus_protocol_required_commands_testing_process_get_device_info_invalid_len (CuTest *test,
	struct cmd_interface *cmd);
void cerberus_protocol_required_commands_testing_process_get_device_info_bad_info_index (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_required_commands_testing_process_get_device_info_fail (CuTest *test,
	struct cmd_interface *cmd, struct cmd_device_mock *cmd_device);

void cerberus_protocol_required_commands_testing_process_get_device_id (CuTest *test,
	struct cmd_interface *cmd, uint16_t vendor_id, uint16_t device_id, uint16_t subsystem_vid,
	uint16_t subsystem_id);
void cerberus_protocol_required_commands_testing_process_get_device_id_invalid_len (CuTest *test,
	struct cmd_interface *cmd);

void cerberus_protocol_required_commands_testing_process_reset_counter (CuTest *test,
	struct cmd_interface *cmd, struct cmd_device_mock *cmd_device);
void cerberus_protocol_required_commands_testing_process_reset_counter_port0 (CuTest *test,
	struct cmd_interface *cmd, struct cmd_device_mock *cmd_device);
void cerberus_protocol_required_commands_testing_process_reset_counter_port1 (CuTest *test,
	struct cmd_interface *cmd, struct cmd_device_mock *cmd_device);
void cerberus_protocol_required_commands_testing_process_reset_counter_invalid_len (CuTest *test,
	struct cmd_interface *cmd);
void cerberus_protocol_required_commands_testing_process_reset_counter_invalid_counter (
	CuTest *test, struct cmd_interface *cmd, struct cmd_device_mock *cmd_device);

void cerberus_protocol_master_commands_testing_process_error_response (CuTest *test,
	struct cmd_interface *cmd, struct cmd_interface_msg *response);
void cerberus_protocol_master_commands_testing_process_error_response_invalid_len (CuTest *test,
	struct cmd_interface *cmd, struct cmd_interface_msg *response);

void cerberus_protocol_required_commands_testing_generate_error_packet (CuTest *test,
	struct cmd_interface *cmd);
void cerberus_protocol_required_commands_testing_generate_error_packet_encrypted (CuTest *test,
	struct cmd_interface *cmd, struct session_manager_mock *session);
void cerberus_protocol_required_commands_testing_generate_error_packet_encrypted_fail (CuTest *test,
	struct cmd_interface *cmd, struct session_manager_mock *session);
void cerberus_protocol_required_commands_testing_generate_error_packet_invalid_arg (CuTest *test,
	struct cmd_interface *cmd);


#endif /* CERBERUS_PROTOCOL_REQUIRED_COMMANDS_TESTING_H_ */
