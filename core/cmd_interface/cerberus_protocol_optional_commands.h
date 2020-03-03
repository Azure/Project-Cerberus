// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_PROTOCOL_OPTIONAL_COMMANDS_H_
#define CERBERUS_PROTOCOL_OPTIONAL_COMMANDS_H_

#include <stdint.h>
#include <stdbool.h>
#include "attestation/pcr_store.h"
#include "crypto/hash.h"
#include "host_fw/host_processor.h"
#include "host_fw/host_control.h"
#include "firmware/firmware_update_control.h"
#include "manifest/pfm/pfm_manager.h"
#include "manifest/manifest_cmd_interface.h"
#include "attestation/attestation.h"
#include "cmd_authorization.h"
#include "cmd_background.h"
#include "cmd_interface.h"
#include "recovery/recovery_image_cmd_interface.h"
#include "recovery/recovery_image_manager.h"


/**
 * Identifier for the type of system log.
 */
enum {
	CERBERUS_PROTOCOL_DEBUG_LOG = 1,						/**< Debug log type. */
	CERBERUS_PROTOCOL_TCG_LOG,								/**< TCG log type. */
	CERBERUS_PROTOCOL_TAMPER_LOG,							/**< Tamper log type. */
	NUM_CERBERUS_PROTOCOL_LOG_TYPES							/**< Number of log types. */
};


#pragma pack(push, 1)
/**
 * Cerberus protocol prepare PFM update request packet format
 */
struct cerberus_protocol_prepare_pfm_update_request_packet {
	uint8_t port_id;										/**< Port ID */
	uint32_t size;											/**< Update size */
};

/**
 * Cerberus protocol PFM update header format
 */
struct cerberus_protocol_pfm_update_header_packet {
	uint8_t port_id;										/**< Port ID */
};

/**
 * Cerberus protocol complete PFM update request packet format
 */
struct cerberus_protocol_complete_pfm_update_request_packet {
	uint8_t port_id;										/**< Port ID */
	uint8_t activation_setting;								/**< 0 for after reboot, 1 to activate immediately */
};

/**
 * Cerberus protocol get PFM ID request packet format
 */
struct cerberus_protocol_get_pfm_id_request_packet {
	uint8_t port_id;										/**< Port ID */
	uint8_t region;											/**< 0 for active, 1 for staging */
};

/**
 * Cerberus protocol get PFM ID response packet format
 */
struct cerberus_protocol_get_pfm_id_response_packet {
	uint8_t valid;											/**< Port contains valid PFM */
	uint32_t id;											/**< PFM ID */
};

/**
 * Cerberus protocol get PFM supported FW request packet format
 */
struct cerberus_protocol_get_pfm_supported_fw_request_packet {
	uint8_t port_id;										/**< Port ID */
	uint8_t region;											/**< 0 for active, 1 for staging */
	uint32_t offset;										/**< Offset to start response at */
};

/**
 * Cerberus protocol get PFM supported FW header format
 */
struct cerberus_protocol_get_pfm_supported_fw_header {
	uint8_t valid;											/**< Port contains valid PFM */
	uint32_t id;											/**< PFM ID */
};

/**
 * Cerberus protocol get update status request packet format
 */
struct cerberus_protocol_get_update_status_request_packet {
	uint8_t update_type;									/**< Update type */
	uint8_t port_id;										/**< Port ID */
};

/**
 * Cerberus protocol get update status response packet format
 */
struct cerberus_protocol_get_update_status_response_packet {
	uint32_t update_status;									/**< Update status */
};

/**
 * Cerberus protocol get extended update status request packet format
 */
struct cerberus_protocol_get_ext_update_status_request_packet {
	uint8_t update_type;									/**< Update type */
	uint8_t port_id;										/**< Port ID */
};

/**
 * Cerberus protocol get extended update status response packet format
 */
struct cerberus_protocol_get_ext_update_status_response_packet {
	uint32_t update_status;									/**< Update status */
	uint32_t remaining_len;									/**< Number of bytes expected to still be sent */
};

/**
 * Cerberus protocol prepare a host recovery image update request packet format
 */
struct cerberus_protocol_prepare_recovery_image_update_request_packet {
	uint8_t port_id;										/**< Port ID */
	uint32_t size;											/**< Update size */
};

/**
 * Cerberus protocol host recovery image update header packet format
 */
struct cerberus_protocol_recovery_image_update_header_packet {
	uint8_t port_id;										/**< Port ID */
};

/**
 * Cerberus protocol host recovery image activate update request packet format
 */
struct cerberus_protocol_activate_recovery_image_update_request_packet {
	uint8_t port_id;										/**< Port ID */
};

/**
 * Cerberus protocol get host recovery image version update request packet format
 */
struct cerberus_protocol_get_recovery_image_version_update_request_packet {
	uint8_t port_id;										/**< Port ID */
};

/**
 * Cerberus protocol get host recovery image version update response packet format
 */
struct cerberus_protocol_get_recovery_image_version_update_response_packet {
	char version[32];							/**< Version ID */
};

/**
 * Cerberus protocol get host reset status request packet format
 */
struct cerberus_protocol_get_host_state_request_packet {
	uint8_t port_id;										/**< Port ID */
};

/**
 * Cerberus protocol get host reset status response packet format
 */
struct cerberus_protocol_get_host_state_response_packet {
	uint8_t reset_status;									/**< Host reset status */
};

/**
 * Cerberus protocol update platform measurement register request packet format
 */
struct cerberus_protocol_update_pcr_request_packet {
	uint8_t measurement_number;								/**< Index for the measurement to update. */
	uint8_t measurement_ext[32];							/**< Measurement to use for update. */
};
#pragma pack(pop)


int cerberus_protocol_fw_update_init (struct firmware_update_control *control,
	struct cmd_interface_request *request);
int cerberus_protocol_fw_update (struct firmware_update_control *control,
	struct cmd_interface_request *request);
int cerberus_protocol_fw_update_start (struct firmware_update_control *control,
	struct cmd_interface_request *request);

int cerberus_protocol_get_log_info (struct pcr_store *pcr_store,
	struct cmd_interface_request *request);
int cerberus_protocol_log_read (struct pcr_store *pcr_store, struct hash_engine *hash,
	struct cmd_interface_request *request);
int cerberus_protocol_log_clear (struct cmd_background *background,
	struct cmd_interface_request *request);
int cerberus_protocol_debug_fill_log (struct cmd_background *background,
	struct cmd_interface_request *request);

int cerberus_protocol_get_pfm_id (struct pfm_manager *pfm_mgr_0, struct pfm_manager *pfm_mgr_1,
	struct cmd_interface_request *request);
int cerberus_protocol_get_pfm_fw (struct manifest_cmd_interface *pfm_0,
	struct manifest_cmd_interface *pfm_1, struct pfm_manager *pfm_mgr_0,
	struct pfm_manager *pfm_mgr_1, struct cmd_interface_request *request);

int cerberus_protocol_pfm_update_init (struct manifest_cmd_interface *pfm_0,
	struct manifest_cmd_interface *pfm_1, struct cmd_interface_request *request);
int cerberus_protocol_pfm_update (struct manifest_cmd_interface *pfm_0,
	struct manifest_cmd_interface *pfm_1, struct cmd_interface_request *request);
int cerberus_protocol_pfm_update_complete (struct manifest_cmd_interface *pfm_0,
	struct manifest_cmd_interface *pfm_1, struct cmd_interface_request *request,
	bool delayed_activation_allowed);
int cerberus_protocol_get_pfm_update_status (struct manifest_cmd_interface *pfm_0,
	struct manifest_cmd_interface *pfm_1, struct cmd_interface_request *request);

int cerberus_protocol_get_host_next_verification_status (struct host_processor *host_0,
	struct host_processor *host_1, struct cmd_interface_request *request);
int cerberus_protocol_get_host_reset_status (struct host_control *host_0_ctrl,
	struct host_control *host_1_ctrl, struct cmd_interface_request *request);

int cerberus_protocol_get_update_status (struct firmware_update_control *control,
	struct manifest_cmd_interface *pfm_0, struct manifest_cmd_interface *pfm_1,
	struct manifest_cmd_interface *cfm, struct manifest_cmd_interface *pcd,
	struct host_processor *host_0, struct host_processor *host_1,
	struct recovery_image_cmd_interface *recovery_0,
	struct recovery_image_cmd_interface *recovery_1, struct cmd_background *background,
	struct cmd_interface_request *request);

int cerberus_protocol_get_extended_update_status (struct firmware_update_control *control,
	struct recovery_image_manager *recovery_manager_0,
	struct recovery_image_manager *recovery_manager_1,
	struct recovery_image_cmd_interface *recovery_cmd_0,
	struct recovery_image_cmd_interface *recovery_cmd_1, struct cmd_interface_request *request);

int cerberus_protocol_unseal_message (struct cmd_background *background,
	struct cmd_interface_request *request, int direction, uint8_t platform_pcr);
int cerberus_protocol_unseal_message_result (struct cmd_background *background,
	struct cmd_interface_request *request, int direction);
	
int cerberus_protocol_reset_config (struct cmd_authorization *cmd_auth,
	struct cmd_background *background, struct cmd_interface_request *request);

int cerberus_protocol_prepare_recovery_image (
	struct recovery_image_cmd_interface *recovery_0,
	struct recovery_image_cmd_interface *recovery_1,
	struct cmd_interface_request *request);
int cerberus_protocol_update_recovery_image (struct recovery_image_cmd_interface *recovery_0,
	struct recovery_image_cmd_interface *recovery_1, struct cmd_interface_request *request);
int cerberus_protocol_activate_recovery_image (struct recovery_image_cmd_interface *recovery_0,
	struct recovery_image_cmd_interface *recovery_1, struct cmd_interface_request *request);
int cerberus_protocol_get_recovery_image_version (struct recovery_image_manager *manager_0,
	struct recovery_image_manager *manager_1, struct cmd_interface_request *request);


#endif // CERBERUS_PROTOCOL_OPTIONAL_COMMANDS_H_
