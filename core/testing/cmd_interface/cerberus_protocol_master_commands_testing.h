// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_PROTOCOL_MASTER_COMMANDS_TESTING_H_
#define CERBERUS_PROTOCOL_MASTER_COMMANDS_TESTING_H_

#include <stdint.h>
#include <stddef.h>
#include "testing.h"
#include "cmd_interface/cmd_interface.h"
#include "testing/mock/attestation/attestation_master_mock.h"
#include "testing/mock/cmd_interface/cmd_background_mock.h"
#include "testing/mock/firmware/firmware_update_control_mock.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/mock/host_fw/host_processor_mock.h"
#include "testing/mock/manifest/manifest_cmd_interface_mock.h"
#include "testing/mock/manifest/cfm_manager_mock.h"
#include "testing/mock/manifest/pcd_manager_mock.h"
#include "testing/mock/recovery/recovery_image_cmd_interface_mock.h"
#include "testing/mock/recovery/recovery_image_manager_mock.h"


void cerberus_protocol_master_commands_testing_process_response_get_certificate_digest (
	CuTest *test, struct cmd_interface *cmd, struct cmd_interface_msg *response);
void cerberus_protocol_master_commands_testing_process_response_get_certificate_digest_invalid_buf_len (
	CuTest *test, struct cmd_interface *cmd);

void cerberus_protocol_master_commands_testing_process_response_get_certificate (CuTest *test,
	struct cmd_interface *cmd, struct cmd_interface_msg *response);
void cerberus_protocol_master_commands_testing_process_response_get_certificate_invalid_buf_len (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_response_get_certificate_unsupported_slot (
	CuTest *test, struct cmd_interface *cmd);

void cerberus_protocol_master_commands_testing_process_response_challenge_response (CuTest *test,
	struct cmd_interface *cmd, struct cmd_interface_msg *response);
void cerberus_protocol_master_commands_testing_process_response_challenge_invalid_buf_len (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_response_challenge_unsupported_slot (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_response_challenge_rsvd_not_zero (
	CuTest *test, struct cmd_interface *cmd);

void cerberus_protocol_master_commands_testing_process_cfm_update_init (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *cfm);
void cerberus_protocol_master_commands_testing_process_cfm_update_init_invalid_len (CuTest *test,
	struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_cfm_update_init_no_cfm_manager (CuTest *test,
	struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_cfm_update_init_fail (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *cfm);

void cerberus_protocol_master_commands_testing_process_cfm_update (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *cfm);
void cerberus_protocol_master_commands_testing_process_cfm_update_no_data (CuTest *test,
	struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_cfm_update_no_cfm_manager (CuTest *test,
	struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_cfm_update_fail (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *cfm);

void cerberus_protocol_master_commands_testing_process_cfm_update_complete (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *cfm);
void cerberus_protocol_master_commands_testing_process_cfm_update_complete_immediate (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *cfm);
void cerberus_protocol_master_commands_testing_process_cfm_update_complete_invalid_len (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_cfm_update_complete_no_cfm_manager (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_cfm_update_complete_fail (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *cfm);

void cerberus_protocol_master_commands_testing_process_get_cfm_id_region0 (CuTest *test,
	struct cmd_interface *cmd, struct cfm_manager_mock *cfm_manager);
void cerberus_protocol_master_commands_testing_process_get_cfm_id_region1 (CuTest *test,
	struct cmd_interface *cmd, struct cfm_manager_mock *cfm_manager);
void cerberus_protocol_master_commands_testing_process_get_cfm_id_no_id_type (CuTest *test,
	struct cmd_interface *cmd, struct cfm_manager_mock *cfm_manager);
void cerberus_protocol_master_commands_testing_process_get_cfm_id_invalid_len (CuTest *test,
	struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_cfm_id_invalid_region (CuTest *test,
	struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_cfm_id_fail (CuTest *test,
	struct cmd_interface *cmd, struct cfm_manager_mock *cfm_manager);
void cerberus_protocol_master_commands_testing_process_get_cfm_id_no_cfm (CuTest *test,
	struct cmd_interface *cmd, struct cfm_manager_mock *cfm_manager);
void cerberus_protocol_master_commands_testing_process_get_cfm_id_no_cfm_manager (CuTest *test,
	struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_cfm_id_invalid_id (CuTest *test,
	struct cmd_interface *cmd);

void cerberus_protocol_master_commands_testing_process_get_cfm_id_platform_region0 (CuTest *test,
	struct cmd_interface *cmd, struct cfm_manager_mock *cfm_manager);
void cerberus_protocol_master_commands_testing_process_get_cfm_id_platform_region1 (CuTest *test,
	struct cmd_interface *cmd, struct cfm_manager_mock *cfm_manager);
void cerberus_protocol_master_commands_testing_process_get_cfm_id_platform_no_cfm (CuTest *test,
	struct cmd_interface *cmd, struct cfm_manager_mock *cfm_manager);
void cerberus_protocol_master_commands_testing_process_get_cfm_id_platform_no_cfm_manager (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_cfm_id_platform_fail (CuTest *test,
	struct cmd_interface *cmd, struct cfm_manager_mock *cfm_manager);

void cerberus_protocol_master_commands_testing_process_get_cfm_component_ids_region0 (CuTest *test,
	struct cmd_interface *cmd, struct cfm_manager_mock *cfm_manager);
void cerberus_protocol_master_commands_testing_process_get_cfm_component_ids_region1 (CuTest *test,
	struct cmd_interface *cmd, struct cfm_manager_mock *cfm_manager);
void cerberus_protocol_master_commands_testing_process_get_cfm_component_ids_nonzero_offset (
	CuTest *test, struct cmd_interface *cmd, struct cfm_manager_mock *cfm_manager);
void cerberus_protocol_master_commands_testing_process_get_cfm_component_ids_limited_response (
	CuTest *test, struct cmd_interface *cmd, struct cfm_manager_mock *cfm_manager);
void cerberus_protocol_master_commands_testing_process_get_cfm_component_ids_no_cfm_manager (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_cfm_component_ids_no_active_cfm (
	CuTest *test, struct cmd_interface *cmd, struct cfm_manager_mock *cfm_manager);
void cerberus_protocol_master_commands_testing_process_get_cfm_component_ids_no_pending_cfm (
	CuTest *test, struct cmd_interface *cmd, struct cfm_manager_mock *cfm_manager);
void cerberus_protocol_master_commands_testing_process_get_cfm_component_ids_fail_id (CuTest *test,
	struct cmd_interface *cmd, struct cfm_manager_mock *cfm_manager);
void cerberus_protocol_master_commands_testing_process_get_cfm_component_ids_fail (CuTest *test,
	struct cmd_interface *cmd, struct cfm_manager_mock *cfm_manager);
void cerberus_protocol_master_commands_testing_process_get_cfm_component_ids_invalid_len (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_cfm_component_ids_invalid_region (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_cfm_component_ids_invalid_offset (
	CuTest *test, struct cmd_interface *cmd, struct cfm_manager_mock *cfm_manager);

void cerberus_protocol_master_commands_testing_process_get_pcd_id (CuTest *test,
	struct cmd_interface *cmd, struct pcd_manager_mock *pcd_manager);
void cerberus_protocol_master_commands_testing_process_get_pcd_id_no_id_type (CuTest *test,
	struct cmd_interface *cmd, struct pcd_manager_mock *pcd_manager);
void cerberus_protocol_master_commands_testing_process_get_pcd_id_no_pcd (CuTest *test,
	struct cmd_interface *cmd, struct pcd_manager_mock *pcd_manager);
void cerberus_protocol_master_commands_testing_process_get_pcd_id_no_pcd_manager (CuTest *test,
	struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_pcd_id_invalid_len (CuTest *test,
	struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_pcd_id_fail (CuTest *test,
	struct cmd_interface *cmd, struct pcd_manager_mock *pcd_manager);
void cerberus_protocol_master_commands_testing_process_get_pcd_id_invalid_id (CuTest *test,
	struct cmd_interface *cmd);

void cerberus_protocol_master_commands_testing_process_get_pcd_id_platform (CuTest *test,
	struct cmd_interface *cmd, struct pcd_manager_mock *pcd_manager);
void cerberus_protocol_master_commands_testing_process_get_pcd_id_platform_no_pcd (CuTest *test,
	struct cmd_interface *cmd, struct pcd_manager_mock *pcd_manager);
void cerberus_protocol_master_commands_testing_process_get_pcd_id_platform_no_pcd_manager (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_pcd_id_platform_fail (CuTest *test,
	struct cmd_interface *cmd, struct pcd_manager_mock *pcd_manager);

void cerberus_protocol_master_commands_testing_process_pcd_update_init (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *pcd);
void cerberus_protocol_master_commands_testing_process_pcd_update_init_no_pcd_manager (CuTest *test,
	struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_pcd_update_init_invalid_len (CuTest *test,
	struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_pcd_update_init_fail (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *pcd);

void cerberus_protocol_master_commands_testing_process_pcd_update (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *pcd);
void cerberus_protocol_master_commands_testing_process_pcd_update_no_data (CuTest *test,
	struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_pcd_update_no_pcd_manager (CuTest *test,
	struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_pcd_update_fail (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *pcd);

void cerberus_protocol_master_commands_testing_process_pcd_update_complete (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *pcd);
void cerberus_protocol_master_commands_testing_process_pcd_update_complete_no_pcd_manager (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_pcd_update_complete_invalid_len (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_pcd_update_complete_fail (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *pcd);

void cerberus_protocol_master_commands_testing_process_get_fw_update_status (CuTest *test,
	struct cmd_interface *cmd, struct firmware_update_control_mock *update);
void cerberus_protocol_master_commands_testing_process_get_fw_update_status_no_fw_update (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_pfm_update_status_port0 (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *pfm_0);
void cerberus_protocol_master_commands_testing_process_get_pfm_update_status_port1 (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *pfm_1);
void cerberus_protocol_master_commands_testing_process_get_pfm_update_status_port0_null (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_pfm_update_status_port1_null (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_pfm_update_status_invalid_port (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_cfm_update_status (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *cfm);
void cerberus_protocol_master_commands_testing_process_get_cfm_update_status_no_cfm_manager (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_pcd_update_status (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *pcd);
void cerberus_protocol_master_commands_testing_process_get_pcd_update_status_no_pcd_manager (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_host_fw_reset_verification_status_port0 (
	CuTest *test, struct cmd_interface *cmd, struct host_processor_mock *host_0);
void cerberus_protocol_master_commands_testing_process_get_host_fw_reset_verification_status_port1 (
	CuTest *test, struct cmd_interface *cmd, struct host_processor_mock *host_1);
void cerberus_protocol_master_commands_testing_process_get_host_fw_reset_verification_status_port0_null (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_host_fw_reset_verification_status_port1_null (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_host_fw_reset_verification_status_invalid_port (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_host_fw_reset_verification_status_fail (
	CuTest *test, struct cmd_interface *cmd, struct host_processor_mock *host_0);
void cerberus_protocol_master_commands_testing_process_get_recovery_image_update_status_port0 (
	CuTest *test, struct cmd_interface *cmd, struct recovery_image_cmd_interface_mock *recovery_0);
void cerberus_protocol_master_commands_testing_process_get_recovery_image_update_status_port1 (
	CuTest *test, struct cmd_interface *cmd, struct recovery_image_cmd_interface_mock *recovery_1);
void cerberus_protocol_master_commands_testing_process_get_recovery_image_update_status_port0_null (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_recovery_image_update_status_port1_null (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_recovery_image_update_status_bad_port_index (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_reset_config_status (CuTest *test,
	struct cmd_interface *cmd, struct cmd_background_mock *background);
void cerberus_protocol_master_commands_testing_process_get_reset_config_status_unsupported (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_update_status_invalid_len (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_update_status_invalid_type (
	CuTest *test, struct cmd_interface *cmd);

void cerberus_protocol_master_commands_testing_process_get_fw_ext_update_status (CuTest *test,
	struct cmd_interface *cmd, struct firmware_update_control_mock *update);
void cerberus_protocol_master_commands_testing_process_get_fw_ext_update_status_no_fw_update (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_pfm_ext_update_status_port0 (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_pfm_ext_update_status_port1 (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_cfm_ext_update_status (CuTest *test,
	struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_pcd_ext_update_status (CuTest *test,
	struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_host_fw_reset_verification_ext_status_port0 (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_host_fw_reset_verification_ext_status_port1 (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_recovery_image_ext_update_status_port0 (
	CuTest *test, struct cmd_interface *cmd, struct recovery_image_cmd_interface_mock *recovery_0,
	struct recovery_image_manager_mock *recovery_manager_0, struct flash_mock *flash);
void cerberus_protocol_master_commands_testing_process_get_recovery_image_ext_update_status_port1 (
	CuTest *test, struct cmd_interface *cmd, struct recovery_image_cmd_interface_mock *recovery_1,
	struct recovery_image_manager_mock *recovery_manager_1, struct flash_mock *flash);
void cerberus_protocol_master_commands_testing_process_get_recovery_image_ext_update_status_port0_null (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_recovery_image_ext_update_status_port0_cmd_intf_null (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_recovery_image_ext_update_status_port1_null (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_recovery_image_ext_update_status_port1_cmd_intf_null (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_recovery_image_ext_update_status_bad_port_index (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_reset_config_ext_update_status (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_ext_update_status_invalid_len (
	CuTest *test, struct cmd_interface *cmd);
void cerberus_protocol_master_commands_testing_process_get_ext_update_status_invalid_type (
	CuTest *test, struct cmd_interface *cmd);


#endif /* CERBERUS_PROTOCOL_MASTER_COMMANDS_TESTING_H_ */
