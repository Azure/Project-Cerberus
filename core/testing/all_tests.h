// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ALL_TESTS_H_
#define ALL_TESTS_H_

#include "CuTest/CuTest.h"
#include "platform_all_tests.h"


//#define	TESTING_RUN_FLASH_COMMON_SUITE
//#define	TESTING_RUN_SPI_FLASH_SUITE
//#define	TESTING_RUN_HASH_MBEDTLS_SUITE
//#define	TESTING_RUN_HASH_SUITE
//#define	TESTING_RUN_RSA_MBEDTLS_SUITE
//#define	TESTING_RUN_FLASH_UTIL_SUITE
//#define	TESTING_RUN_APP_IMAGE_SUITE
//#define	TESTING_RUN_FIRMWARE_UPDATE_SUITE
//#define	TESTING_RUN_HOST_FW_UTIL_SUITE
//#define	TESTING_RUN_MANIFEST_FLASH_SUITE
//#define	TESTING_RUN_PFM_FLASH_SUITE
//#define	TESTING_RUN_CFM_FLASH_SUITE
//#define	TESTING_RUN_CERBERUS_PROTOCOL_REQUIRED_COMMANDS_SUITE
//#define	TESTING_RUN_CERBERUS_PROTOCOL_MASTER_COMMANDS_SUITE
//#define	TESTING_RUN_CERBERUS_PROTOCOL_OPTIONAL_COMMANDS_SUITE
//#define	TESTING_RUN_CERBERUS_PROTOCOL_DEBUG_COMMANDS_SUITE
//#define	TESTING_RUN_CERBERUS_PROTOCOL_DIAGNOSTIC_COMMANDS_SUITE
//#define	TESTING_RUN_CMD_INTERFACE_SYSTEM_SUITE
//#define	TESTING_RUN_CMD_INTERFACE_SLAVE_SUITE
//#define	TESTING_RUN_CMD_INTERFACE_DUAL_CMD_SET_SUITE
//#define	TESTING_RUN_MCTP_PROTOCOL_SUITE
//#define	TESTING_RUN_STATE_MANAGER_SUITE
//#define	TESTING_RUN_HOST_STATE_MANAGER_SUITE
//#define	TESTING_RUN_SYSTEM_STATE_MANAGER_SUITE
//#define	TESTING_RUN_HOST_FLASH_MANAGER_SUITE
//#define	TESTING_RUN_PFM_MANAGER_FLASH_SUITE
//#define	TESTING_RUN_CFM_MANAGER_FLASH_SUITE
//#define	TESTING_RUN_HOST_PROCESSOR_SUITE
//#define	TESTING_RUN_HOST_PROCESSOR_DUAL_SUITE
//#define	TESTING_RUN_HOST_IRQ_HANDLER_SUITE
//#define	TESTING_RUN_SPI_FILTER_IRQ_HANDLER_SUITE
//#define	TESTING_RUN_PLATFORM_TIMER_SUITE
//#define	TESTING_RUN_BMC_RECOVERY_SUITE
//#define	TESTING_RUN_LOGGING_FLASH_SUITE
//#define	TESTING_RUN_LOGGING_MEMORY_SUITE
//#define	TESTING_RUN_CHECKSUM_SUITE
//#define	TESTING_RUN_MCTP_INTERFACE_SUITE
//#define	TESTING_RUN_ECC_MBEDTLS_SUITE
//#define	TESTING_RUN_X509_MBEDTLS_SUITE
//#define	TESTING_RUN_AES_MBEDTLS_SUITE
//#define	TESTING_RUN_DEBUG_LOG_SUITE
//#define	TESTING_RUN_RIOT_CORE_COMMON_SUITE
//#define	TESTING_RUN_BASE64_MBEDTLS_SUITE
//#define	TESTING_RUN_KEYSTORE_FLASH_SUITE
//#define	TESTING_RUN_RIOT_KEY_MANAGER_SUITE
//#define	TESTING_RUN_AUX_ATTESTATION_SUITE
//#define	TESTING_RUN_FIRMWARE_HEADER_SUITE
//#define	TESTING_RUN_SPI_FILTER_IRQ_HANDLER_DIRTY_SUITE
//#define	TESTING_RUN_HOST_IRQ_HANDLER_PFM_CHECK_SUITE
//#define	TESTING_RUN_ATTESTATION_MASTER_SUITE
//#define	TESTING_RUN_ATTESTATION_SLAVE_SUITE
//#define	TESTING_RUN_RNG_MBEDTLS_SUITE
//#define	TESTING_RUN_DEVICE_MANAGER_SUITE
//#define	TESTING_RUN_ECC_RIOT_SUITE
//#define	TESTING_RUN_BASE64_RIOT_SUITE
//#define	TESTING_RUN_HASH_RIOT_SUITE
//#define	TESTING_RUN_PCR_SUITE
//#define	TESTING_RUN_PCR_STORE_SUITE
//#define	TESTING_RUN_HOST_IRQ_HANDLER_MASK_IRQS_SUITE
//#define	TESTING_RUN_HOST_PROCESSOR_DUAL_FULL_BYPASS_SUITE
//#define	TESTING_RUN_OBSERVABLE_SUITE
//#define	TESTING_RUN_PFM_MANAGER_SUITE
//#define	TESTING_RUN_CFM_MANAGER_SUITE
//#define	TESTING_RUN_PFM_OBSERVER_PENDING_RESET_SUITE
//#define	TESTING_RUN_PFM_OBSERVER_PCR_SUITE
//#define	TESTING_RUN_CFM_OBSERVER_PCR_SUITE
//#define	TESTING_RUN_SIGNATURE_VERIFICATION_RSA_SUITE
//#define	TESTING_RUN_SIGNATURE_VERIFICATION_ECC_SUITE
//#define	TESTING_RUN_MANIFEST_VERIFICATION_SUITE
//#define	TESTING_RUN_X509_RIOT_SUITE
//#define	TESTING_RUN_RSA_SUITE
//#define	TESTING_RUN_SPI_FLASH_SFDP_SUITE
//#define	TESTING_RUN_HOST_FLASH_INITIALIZATION_SUITE
//#define	TESTING_RUN_RECOVERY_IMAGE_HEADER_SUITE
//#define	TESTING_RUN_RECOVERY_IMAGE_SECTION_HEADER_SUITE
//#define	TESTING_RUN_MANIFEST_MANAGER_SUITE
//#define	TESTING_RUN_SPI_FILTER_SUITE
//#define	TESTING_RUN_IMAGE_HEADER_SUITE
//#define	TESTING_RUN_CMD_CHANNEL_SUITE
//#define	TESTING_RUN_FIRMWARE_COMPONENT_SUITE
//#define	TESTING_RUN_FLASH_UPDATER_SUITE
//#define	TESTING_RUN_TPM_SUITE
//#define	TESTING_RUN_AUTHORIZATION_ALLOWED_SUITE
//#define	TESTING_RUN_AUTHORIZATION_DISALLOWED_SUITE
//#define	TESTING_RUN_AUTHORIZATION_CHALLENGE_SUITE
//#define	TESTING_RUN_CONFIG_RESET_SUITE
//#define	TESTING_RUN_CMD_AUTHORIZATION_SUITE
//#define	TESTING_RUN_RECOVERY_IMAGE_SUITE
//#define	TESTING_RUN_RECOVERY_IMAGE_OBSERVER_PCR_SUITE
//#define	TESTING_RUN_RECOVERY_IMAGE_MANAGER_SUITE
//#define	TESTING_RUN_PCD_MANAGER_SUITE
//#define	TESTING_RUN_PCD_MANAGER_FLASH_SUITE
//#define	TESTING_RUN_PCD_OBSERVER_PCR_SUITE
//#define	TESTING_RUN_PCD_FLASH_SUITE
//#define	TESTING_RUN_MCTP_INTERFACE_CONTROL_SUITE
//#define	TESTING_RUN_HOST_PROCESSOR_OBSERVER_PCR_SUITE
//#define	TESTING_RUN_COUNTER_MANAGER_REGISTERS_SUITE
//#define	TESTING_RUN_SESSION_MANAGER_ECC_SUITE
//#define	TESTING_RUN_BASE64_THREAD_SAFE_SUITE
//#define	TESTING_RUN_ECC_THREAD_SAFE_SUITE
//#define	TESTING_RUN_HASH_THREAD_SAFE_SUITE
//#define	TESTING_RUN_RNG_THREAD_SAFE_SUITE
//#define	TESTING_RUN_RSA_THREAD_SAFE_SUITE
//#define	TESTING_RUN_X509_THREAD_SAFE_SUITE
//#define	TESTING_RUN_FLASH_STORE_SUITE
//#define	TESTING_RUN_FLASH_STORE_ENCRYPTED_SUITE
//#define	TESTING_RUN_KDF_SUITE


CuSuite* get_flash_common_suite (void);
CuSuite* get_spi_flash_suite (void);
CuSuite* get_hash_mbedtls_suite (void);
CuSuite* get_hash_suite (void);
CuSuite* get_rsa_mbedtls_suite (void);
CuSuite* get_flash_util_suite (void);
CuSuite* get_app_image_suite (void);
CuSuite* get_firmware_update_suite (void);
CuSuite* get_host_fw_util_suite (void);
CuSuite* get_manifest_flash_suite (void);
CuSuite* get_manifest_flash_v2_suite (void);
CuSuite* get_pfm_flash_suite (void);
CuSuite* get_pfm_flash_v2_suite (void);
CuSuite* get_cfm_flash_suite (void);
CuSuite* get_cerberus_protocol_required_commands_suite (void);
CuSuite* get_cerberus_protocol_master_commands_suite (void);
CuSuite* get_cerberus_protocol_optional_commands_suite (void);
CuSuite* get_cerberus_protocol_debug_commands_suite (void);
CuSuite* get_cerberus_protocol_diagnostic_commands_suite (void);
CuSuite* get_cmd_interface_system_suite (void);
CuSuite* get_cmd_interface_slave_suite (void);
CuSuite* get_cmd_interface_dual_cmd_set_suite (void);
CuSuite* get_mctp_protocol_suite (void);
CuSuite* get_state_manager_suite (void);
CuSuite* get_host_state_manager_suite (void);
CuSuite* get_system_state_manager_suite (void);
CuSuite* get_host_flash_manager_suite (void);
CuSuite* get_pfm_manager_flash_suite (void);
CuSuite* get_cfm_manager_flash_suite (void);
CuSuite* get_host_processor_suite (void);
CuSuite* get_host_processor_dual_suite (void);
CuSuite* get_host_processor_dual_power_on_reset_suite (void);
CuSuite* get_host_processor_dual_soft_reset_suite (void);
CuSuite* get_host_processor_dual_run_time_verification_suite (void);
CuSuite* get_host_processor_dual_flash_rollback_suite (void);
CuSuite* get_host_processor_dual_apply_recovery_image_suite (void);
CuSuite* get_host_processor_dual_bypass_mode_suite (void);
CuSuite* get_host_irq_handler_suite (void);
CuSuite* get_spi_filter_irq_handler_suite (void);
CuSuite* get_platform_timer_suite (void);
CuSuite* get_bmc_recovery_suite (void);
CuSuite* get_logging_flash_suite (void);
CuSuite* get_logging_memory_suite (void);
CuSuite* get_checksum_suite (void);
CuSuite* get_mctp_interface_suite (void);
CuSuite* get_ecc_mbedtls_suite (void);
CuSuite* get_x509_mbedtls_suite (void);
CuSuite* get_aes_mbedtls_suite (void);
CuSuite* get_debug_log_suite (void);
CuSuite* get_riot_core_common_suite (void);
CuSuite* get_base64_mbedtls_suite (void);
CuSuite* get_keystore_flash_suite (void);
CuSuite* get_riot_key_manager_suite (void);
CuSuite* get_aux_attestation_suite (void);
CuSuite* get_firmware_header_suite (void);
CuSuite* get_spi_filter_irq_handler_dirty_suite (void);
CuSuite* get_host_irq_handler_pfm_check_suite (void);
CuSuite* get_attestation_master_suite (void);
CuSuite* get_attestation_slave_suite (void);
CuSuite* get_rng_mbedtls_suite (void);
CuSuite* get_device_manager_suite (void);
CuSuite* get_ecc_riot_suite (void);
CuSuite* get_base64_riot_suite (void);
CuSuite* get_hash_riot_suite (void);
CuSuite* get_pcr_suite (void);
CuSuite* get_pcr_store_suite (void);
CuSuite* get_host_irq_handler_mask_irqs_suite (void);
CuSuite* get_host_processor_dual_full_bypass_suite (void);
CuSuite* get_observable_suite (void);
CuSuite* get_pfm_manager_suite (void);
CuSuite* get_cfm_manager_suite (void);
CuSuite* get_pfm_observer_pending_reset_suite (void);
CuSuite* get_pfm_observer_pcr_suite (void);
CuSuite* get_cfm_observer_pcr_suite (void);
CuSuite* get_signature_verification_rsa_suite (void);
CuSuite* get_signature_verification_ecc_suite (void);
CuSuite* get_manifest_verification_suite (void);
CuSuite* get_x509_riot_suite (void);
CuSuite* get_rsa_suite (void);
CuSuite* get_spi_flash_sfdp_suite (void);
CuSuite* get_host_flash_initialization_suite (void);
CuSuite* get_recovery_image_header_suite (void);
CuSuite* get_recovery_image_section_header_suite (void);
CuSuite* get_manifest_manager_suite (void);
CuSuite* get_spi_filter_suite (void);
CuSuite* get_image_header_suite (void);
CuSuite* get_cmd_channel_suite (void);
CuSuite* get_firmware_component_suite (void);
CuSuite* get_flash_updater_suite (void);
CuSuite* get_tpm_suite (void);
CuSuite* get_authorization_allowed_suite (void);
CuSuite* get_authorization_disallowed_suite (void);
CuSuite* get_authorization_challenge_suite (void);
CuSuite* get_config_reset_suite (void);
CuSuite* get_cmd_authorization_suite (void);
CuSuite* get_recovery_image_suite (void);
CuSuite* get_recovery_image_observer_pcr_suite (void);
CuSuite* get_recovery_image_manager_suite (void);
CuSuite* get_pcd_manager_suite (void);
CuSuite* get_pcd_manager_flash_suite (void);
CuSuite* get_pcd_observer_pcr_suite (void);
CuSuite* get_pcd_flash_suite (void);
CuSuite* get_mctp_interface_control_suite (void);
CuSuite* get_host_processor_observer_pcr_suite (void);
CuSuite* get_counter_manager_registers_suite (void);
CuSuite* get_session_manager_ecc_suite (void);
CuSuite* get_base64_thread_safe_suite (void);
CuSuite* get_ecc_thread_safe_suite (void);
CuSuite* get_hash_thread_safe_suite (void);
CuSuite* get_rng_thread_safe_suite (void);
CuSuite* get_rsa_thread_safe_suite (void);
CuSuite* get_x509_thread_safe_suite (void);
CuSuite* get_flash_store_suite (void);
CuSuite* get_flash_store_encrypted_suite (void);
CuSuite* get_kdf_suite (void);

void add_all_tests (CuSuite *suite)
{
#ifdef TESTING_RUN_FLASH_COMMON_SUITE
	CuSuiteAddSuite (suite, get_flash_common_suite ());
#endif
#ifdef TESTING_RUN_SPI_FLASH_SUITE
	CuSuiteAddSuite (suite, get_spi_flash_suite ());
#endif
#ifdef TESTING_RUN_HASH_MBEDTLS_SUITE
	CuSuiteAddSuite (suite, get_hash_mbedtls_suite ());
#endif
#ifdef TESTING_RUN_HASH_SUITE
	CuSuiteAddSuite (suite, get_hash_suite ());
#endif
#ifdef TESTING_RUN_RSA_MBEDTLS_SUITE
	CuSuiteAddSuite (suite, get_rsa_mbedtls_suite ());
#endif
#ifdef TESTING_RUN_FLASH_UTIL_SUITE
	CuSuiteAddSuite (suite, get_flash_util_suite ());
#endif
#ifdef TESTING_RUN_APP_IMAGE_SUITE
	CuSuiteAddSuite (suite, get_app_image_suite ());
#endif
#ifdef TESTING_RUN_FIRMWARE_UPDATE_SUITE
	CuSuiteAddSuite (suite, get_firmware_update_suite ());
#endif
#ifdef TESTING_RUN_HOST_FW_UTIL_SUITE
	CuSuiteAddSuite (suite, get_host_fw_util_suite ());
#endif
#ifdef TESTING_RUN_MANIFEST_FLASH_SUITE
	CuSuiteAddSuite (suite, get_manifest_flash_suite ());
	CuSuiteAddSuite (suite, get_manifest_flash_v2_suite ());
#endif
#ifdef TESTING_RUN_PFM_FLASH_SUITE
	CuSuiteAddSuite (suite, get_pfm_flash_suite ());
	CuSuiteAddSuite (suite, get_pfm_flash_v2_suite ());
#endif
#ifdef TESTING_RUN_CFM_FLASH_SUITE
	CuSuiteAddSuite (suite, get_cfm_flash_suite ());
#endif
#ifdef TESTING_RUN_CERBERUS_PROTOCOL_REQUIRED_COMMANDS_SUITE
	CuSuiteAddSuite (suite, get_cerberus_protocol_required_commands_suite ());
#endif
#ifdef TESTING_RUN_CERBERUS_PROTOCOL_MASTER_COMMANDS_SUITE
	CuSuiteAddSuite (suite, get_cerberus_protocol_master_commands_suite ());
#endif
#ifdef TESTING_RUN_CERBERUS_PROTOCOL_OPTIONAL_COMMANDS_SUITE
	CuSuiteAddSuite (suite, get_cerberus_protocol_optional_commands_suite ());
#endif
#ifdef TESTING_RUN_CERBERUS_PROTOCOL_DEBUG_COMMANDS_SUITE
	CuSuiteAddSuite (suite, get_cerberus_protocol_debug_commands_suite ());
#endif
#ifdef TESTING_RUN_CERBERUS_PROTOCOL_DIAGNOSTIC_COMMANDS_SUITE
	CuSuiteAddSuite (suite, get_cerberus_protocol_diagnostic_commands_suite ());
#endif
#ifdef TESTING_RUN_CMD_INTERFACE_SYSTEM_SUITE
	CuSuiteAddSuite (suite, get_cmd_interface_system_suite ());
#endif
#ifdef TESTING_RUN_CMD_INTERFACE_SLAVE_SUITE
	CuSuiteAddSuite (suite, get_cmd_interface_slave_suite ());
#endif
#ifdef TESTING_RUN_CMD_INTERFACE_DUAL_CMD_SET_SUITE
	CuSuiteAddSuite (suite, get_cmd_interface_dual_cmd_set_suite ());
#endif
#ifdef TESTING_RUN_MCTP_PROTOCOL_SUITE
	CuSuiteAddSuite (suite, get_mctp_protocol_suite ());
#endif
#ifdef TESTING_RUN_STATE_MANAGER_SUITE
	CuSuiteAddSuite (suite, get_state_manager_suite ());
#endif
#ifdef TESTING_RUN_HOST_STATE_MANAGER_SUITE
	CuSuiteAddSuite (suite, get_host_state_manager_suite ());
#endif
#ifdef TESTING_RUN_SYSTEM_STATE_MANAGER_SUITE
	CuSuiteAddSuite (suite, get_system_state_manager_suite ());
#endif
#ifdef TESTING_RUN_HOST_FLASH_MANAGER_SUITE
	CuSuiteAddSuite (suite, get_host_flash_manager_suite ());
#endif
#ifdef TESTING_RUN_PFM_MANAGER_FLASH_SUITE
	CuSuiteAddSuite (suite, get_pfm_manager_flash_suite ());
#endif
#ifdef TESTING_RUN_CFM_MANAGER_FLASH_SUITE
	CuSuiteAddSuite (suite, get_cfm_manager_flash_suite ());
#endif
#ifdef TESTING_RUN_HOST_PROCESSOR_SUITE
	CuSuiteAddSuite (suite, get_host_processor_suite ());
#endif
#ifdef TESTING_RUN_HOST_PROCESSOR_DUAL_SUITE
	CuSuiteAddSuite (suite, get_host_processor_dual_suite ());
	CuSuiteAddSuite (suite, get_host_processor_dual_power_on_reset_suite ());
	CuSuiteAddSuite (suite, get_host_processor_dual_soft_reset_suite ());
	CuSuiteAddSuite (suite, get_host_processor_dual_run_time_verification_suite ());
	CuSuiteAddSuite (suite, get_host_processor_dual_flash_rollback_suite ());
	CuSuiteAddSuite (suite, get_host_processor_dual_apply_recovery_image_suite ());
	CuSuiteAddSuite (suite, get_host_processor_dual_bypass_mode_suite ());
#endif
#ifdef TESTING_RUN_HOST_IRQ_HANDLER_SUITE
	CuSuiteAddSuite (suite, get_host_irq_handler_suite ());
#endif
#ifdef TESTING_RUN_SPI_FILTER_IRQ_HANDLER_SUITE
	CuSuiteAddSuite (suite, get_spi_filter_irq_handler_suite ());
#endif
#ifdef TESTING_RUN_PLATFORM_TIMER_SUITE
	CuSuiteAddSuite (suite, get_platform_timer_suite ());
#endif
#ifdef TESTING_RUN_BMC_RECOVERY_SUITE
	CuSuiteAddSuite (suite, get_bmc_recovery_suite ());
#endif
#ifdef TESTING_RUN_LOGGING_FLASH_SUITE
	CuSuiteAddSuite (suite, get_logging_flash_suite ());
#endif
#ifdef TESTING_RUN_LOGGING_MEMORY_SUITE
	CuSuiteAddSuite (suite, get_logging_memory_suite ());
#endif
#ifdef TESTING_RUN_CHECKSUM_SUITE
	CuSuiteAddSuite (suite, get_checksum_suite ());
#endif
#ifdef TESTING_RUN_MCTP_INTERFACE_SUITE
	CuSuiteAddSuite (suite, get_mctp_interface_suite ());
#endif
#ifdef TESTING_RUN_ECC_MBEDTLS_SUITE
	CuSuiteAddSuite (suite, get_ecc_mbedtls_suite ());
#endif
#ifdef TESTING_RUN_X509_MBEDTLS_SUITE
	CuSuiteAddSuite (suite, get_x509_mbedtls_suite ());
#endif
#ifdef TESTING_RUN_AES_MBEDTLS_SUITE
	CuSuiteAddSuite (suite, get_aes_mbedtls_suite ());
#endif
#ifdef TESTING_RUN_DEBUG_LOG_SUITE
	CuSuiteAddSuite (suite, get_debug_log_suite ());
#endif
#ifdef TESTING_RUN_RIOT_CORE_COMMON_SUITE
	CuSuiteAddSuite (suite, get_riot_core_common_suite ());
#endif
#ifdef TESTING_RUN_BASE64_MBEDTLS_SUITE
	CuSuiteAddSuite (suite, get_base64_mbedtls_suite ());
#endif
#ifdef TESTING_RUN_KEYSTORE_FLASH_SUITE
	CuSuiteAddSuite (suite, get_keystore_flash_suite ());
#endif
#ifdef TESTING_RUN_RIOT_KEY_MANAGER_SUITE
	CuSuiteAddSuite (suite, get_riot_key_manager_suite ());
#endif
#ifdef TESTING_RUN_AUX_ATTESTATION_SUITE
	CuSuiteAddSuite (suite, get_aux_attestation_suite ());
#endif
#ifdef TESTING_RUN_FIRMWARE_HEADER_SUITE
	CuSuiteAddSuite (suite, get_firmware_header_suite ());
#endif
#ifdef TESTING_RUN_SPI_FILTER_IRQ_HANDLER_DIRTY_SUITE
	CuSuiteAddSuite (suite, get_spi_filter_irq_handler_dirty_suite ());
#endif
#ifdef TESTING_RUN_HOST_IRQ_HANDLER_PFM_CHECK_SUITE
	CuSuiteAddSuite (suite, get_host_irq_handler_pfm_check_suite ());
#endif
#ifdef TESTING_RUN_ATTESTATION_MASTER_SUITE
	CuSuiteAddSuite (suite, get_attestation_master_suite ());
#endif
#ifdef TESTING_RUN_ATTESTATION_SLAVE_SUITE
	CuSuiteAddSuite (suite, get_attestation_slave_suite ());
#endif
#ifdef TESTING_RUN_RNG_MBEDTLS_SUITE
	CuSuiteAddSuite (suite, get_rng_mbedtls_suite ());
#endif
#ifdef TESTING_RUN_DEVICE_MANAGER_SUITE
	CuSuiteAddSuite (suite, get_device_manager_suite ());
#endif
#ifdef TESTING_RUN_ECC_RIOT_SUITE
	CuSuiteAddSuite (suite, get_ecc_riot_suite ());
#endif
#ifdef TESTING_RUN_BASE64_RIOT_SUITE
	CuSuiteAddSuite (suite, get_base64_riot_suite ());
#endif
#ifdef TESTING_RUN_HASH_RIOT_SUITE
	CuSuiteAddSuite (suite, get_hash_riot_suite ());
#endif
#ifdef TESTING_RUN_PCR_SUITE
	CuSuiteAddSuite (suite, get_pcr_suite ());
#endif
#ifdef TESTING_RUN_PCR_STORE_SUITE
	CuSuiteAddSuite (suite, get_pcr_store_suite ());
#endif
#ifdef TESTING_RUN_HOST_IRQ_HANDLER_MASK_IRQS_SUITE
	CuSuiteAddSuite (suite, get_host_irq_handler_mask_irqs_suite ());
#endif
#ifdef TESTING_RUN_HOST_PROCESSOR_DUAL_FULL_BYPASS_SUITE
	CuSuiteAddSuite (suite, get_host_processor_dual_full_bypass_suite ());
#endif
#ifdef TESTING_RUN_OBSERVABLE_SUITE
	CuSuiteAddSuite (suite, get_observable_suite ());
#endif
#ifdef TESTING_RUN_PFM_MANAGER_SUITE
	CuSuiteAddSuite (suite, get_pfm_manager_suite ());
#endif
#ifdef TESTING_RUN_CFM_MANAGER_SUITE
	CuSuiteAddSuite (suite, get_cfm_manager_suite ());
#endif
#ifdef TESTING_RUN_PFM_OBSERVER_PENDING_RESET_SUITE
	CuSuiteAddSuite (suite, get_pfm_observer_pending_reset_suite ());
#endif
#ifdef TESTING_RUN_PFM_OBSERVER_PCR_SUITE
	CuSuiteAddSuite (suite, get_pfm_observer_pcr_suite ());
#endif
#ifdef TESTING_RUN_CFM_OBSERVER_PCR_SUITE
	CuSuiteAddSuite (suite, get_cfm_observer_pcr_suite ());
#endif
#ifdef TESTING_RUN_SIGNATURE_VERIFICATION_RSA_SUITE
	CuSuiteAddSuite (suite, get_signature_verification_rsa_suite ());
#endif
#ifdef TESTING_RUN_SIGNATURE_VERIFICATION_ECC_SUITE
	CuSuiteAddSuite (suite, get_signature_verification_ecc_suite ());
#endif
#ifdef TESTING_RUN_MANIFEST_VERIFICATION_SUITE
	CuSuiteAddSuite (suite, get_manifest_verification_suite ());
#endif
#ifdef TESTING_RUN_X509_RIOT_SUITE
	CuSuiteAddSuite (suite, get_x509_riot_suite ());
#endif
#ifdef TESTING_RUN_RSA_SUITE
	CuSuiteAddSuite (suite, get_rsa_suite ());
#endif
#ifdef TESTING_RUN_SPI_FLASH_SFDP_SUITE
	CuSuiteAddSuite (suite, get_spi_flash_sfdp_suite ());
#endif
#ifdef TESTING_RUN_HOST_FLASH_INITIALIZATION_SUITE
	CuSuiteAddSuite (suite, get_host_flash_initialization_suite ());
#endif
#ifdef TESTING_RUN_RECOVERY_IMAGE_HEADER_SUITE
	CuSuiteAddSuite (suite, get_recovery_image_header_suite ());
#endif
#ifdef TESTING_RUN_RECOVERY_IMAGE_SECTION_HEADER_SUITE
	CuSuiteAddSuite (suite, get_recovery_image_section_header_suite ());
#endif
#ifdef TESTING_RUN_MANIFEST_MANAGER_SUITE
	CuSuiteAddSuite (suite, get_manifest_manager_suite ());
#endif
#ifdef TESTING_RUN_SPI_FILTER_SUITE
	CuSuiteAddSuite (suite, get_spi_filter_suite ());
#endif
#ifdef TESTING_RUN_IMAGE_HEADER_SUITE
	CuSuiteAddSuite (suite, get_image_header_suite ());
#endif
#ifdef TESTING_RUN_CMD_CHANNEL_SUITE
	CuSuiteAddSuite (suite, get_cmd_channel_suite ());
#endif
#ifdef TESTING_RUN_FIRMWARE_COMPONENT_SUITE
	CuSuiteAddSuite (suite, get_firmware_component_suite ());
#endif
#ifdef TESTING_RUN_FLASH_UPDATER_SUITE
	CuSuiteAddSuite (suite, get_flash_updater_suite ());
#endif
#ifdef TESTING_RUN_TPM_SUITE
	CuSuiteAddSuite(suite, get_tpm_suite ());
#endif
#ifdef TESTING_RUN_AUTHORIZATION_ALLOWED_SUITE
	CuSuiteAddSuite (suite, get_authorization_allowed_suite ());
#endif
#ifdef TESTING_RUN_AUTHORIZATION_DISALLOWED_SUITE
	CuSuiteAddSuite (suite, get_authorization_disallowed_suite ());
#endif
#ifdef TESTING_RUN_AUTHORIZATION_CHALLENGE_SUITE
	CuSuiteAddSuite (suite, get_authorization_challenge_suite ());
#endif
#ifdef TESTING_RUN_CONFIG_RESET_SUITE
	CuSuiteAddSuite (suite, get_config_reset_suite ());
#endif
#ifdef TESTING_RUN_CMD_AUTHORIZATION_SUITE
	CuSuiteAddSuite (suite, get_cmd_authorization_suite ());
#endif
#ifdef TESTING_RUN_RECOVERY_IMAGE_SUITE
	CuSuiteAddSuite (suite, get_recovery_image_suite ());
#endif
#ifdef TESTING_RUN_RECOVERY_IMAGE_OBSERVER_PCR_SUITE
	CuSuiteAddSuite (suite, get_recovery_image_observer_pcr_suite ());
#endif
#ifdef TESTING_RUN_RECOVERY_IMAGE_MANAGER_SUITE
	CuSuiteAddSuite (suite, get_recovery_image_manager_suite ());
#endif
#ifdef TESTING_RUN_PCD_MANAGER_SUITE
	CuSuiteAddSuite (suite, get_pcd_manager_suite ());
#endif
#ifdef TESTING_RUN_PCD_MANAGER_FLASH_SUITE
	CuSuiteAddSuite (suite, get_pcd_manager_flash_suite ());
#endif
#ifdef TESTING_RUN_PCD_OBSERVER_PCR_SUITE
	CuSuiteAddSuite (suite, get_pcd_observer_pcr_suite ());
#endif
#ifdef TESTING_RUN_PCD_FLASH_SUITE
	CuSuiteAddSuite (suite, get_pcd_flash_suite ());
#endif
#ifdef TESTING_RUN_MCTP_INTERFACE_CONTROL_SUITE
	CuSuiteAddSuite (suite, get_mctp_interface_control_suite ());
#endif
#ifdef TESTING_RUN_HOST_PROCESSOR_OBSERVER_PCR_SUITE
	CuSuiteAddSuite (suite, get_host_processor_observer_pcr_suite ());
#endif
#ifdef TESTING_RUN_COUNTER_MANAGER_REGISTERS_SUITE
	CuSuiteAddSuite (suite, get_counter_manager_registers_suite ());
#endif
#ifdef TESTING_RUN_SESSION_MANAGER_ECC_SUITE
	CuSuiteAddSuite (suite, get_session_manager_ecc_suite ());
#endif
#ifdef TESTING_RUN_BASE64_THREAD_SAFE_SUITE
	CuSuiteAddSuite (suite, get_base64_thread_safe_suite ());
#endif
#ifdef TESTING_RUN_ECC_THREAD_SAFE_SUITE
	CuSuiteAddSuite (suite, get_ecc_thread_safe_suite ());
#endif
#ifdef TESTING_RUN_HASH_THREAD_SAFE_SUITE
	CuSuiteAddSuite (suite, get_hash_thread_safe_suite ());
#endif
#ifdef TESTING_RUN_RNG_THREAD_SAFE_SUITE
	CuSuiteAddSuite (suite, get_rng_thread_safe_suite ());
#endif
#ifdef TESTING_RUN_RSA_THREAD_SAFE_SUITE
	CuSuiteAddSuite (suite, get_rsa_thread_safe_suite ());
#endif
#ifdef TESTING_RUN_X509_THREAD_SAFE_SUITE
	CuSuiteAddSuite (suite, get_x509_thread_safe_suite ());
#endif
#ifdef TESTING_RUN_FLASH_STORE_SUITE
	CuSuiteAddSuite (suite, get_flash_store_suite ());
#endif
#ifdef TESTING_RUN_FLASH_STORE_ENCRYPTED_SUITE
	CuSuiteAddSuite (suite, get_flash_store_encrypted_suite ());
#endif
#ifdef TESTING_RUN_KDF_SUITE
	CuSuiteAddSuite (suite, get_kdf_suite ());
#endif

	add_all_platform_tests (suite);
}


#endif /* ALL_TESTS_H_ */
