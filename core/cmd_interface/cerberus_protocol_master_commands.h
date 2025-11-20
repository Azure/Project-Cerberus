// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_PROTOCOL_MASTER_COMMANDS_H_
#define CERBERUS_PROTOCOL_MASTER_COMMANDS_H_

#include <stdbool.h>
#include <stdint.h>
#include "cmd_interface/cerberus_protocol.h"
#include "cmd_interface/cmd_background.h"
#include "cmd_interface/cmd_interface.h"
#include "cmd_interface/device_manager.h"
#include "crypto/rng.h"
#include "firmware/firmware_update_control.h"
#include "host_fw/host_cmd_interface.h"
#include "manifest/cfm/cfm_manager.h"
#include "manifest/manifest_cmd_interface.h"
#include "manifest/pcd/pcd_manager.h"
#include "recovery/recovery_image_cmd_interface.h"
#include "recovery/recovery_image_manager.h"


/**
 * Identifier for the type of update status.
 */
enum {
	CERBERUS_PROTOCOL_FW_UPDATE_STATUS = 0,			/**< Cerberus FW update */
	CERBERUS_PROTOCOL_PFM_UPDATE_STATUS,			/**< PFM update */
	CERBERUS_PROTOCOL_CFM_UPDATE_STATUS,			/**< CFM update */
	CERBERUS_PROTOCOL_PCD_UPDATE_STATUS,			/**< PCD update */
	CERBERUS_PROTOCOL_HOST_FW_NEXT_RESET,			/**< Host FW reset verification */
	CERBERUS_PROTOCOL_RECOVERY_IMAGE_UPDATE_STATUS,	/**< Recovery image update */
	CERBERUS_PROTOCOL_CONFIG_RESET_STATUS,			/**< Configuration reset */
	CERBERUS_PROTOCOL_HOST_FLASH_CONFIG_STATUS,		/**< Host flash configuration */
};

/**
 * Identifier for the type of manifest ID.
 */
enum {
	CERBERUS_PROTOCOL_ID_VERSION = 0,	/**< Request a manifest version ID */
	CERBERUS_PROTOCOL_ID_PLATFORM,		/**< Request a manifest platform ID */
};

#pragma pack(push, 1)
/**
 * Cerberus protocol get component firmware manifest ID request format
 */
struct cerberus_protocol_get_cfm_id {
	struct cerberus_protocol_header header;	/**< Message header */
	uint8_t region;							/**< Manifest region to query */
	uint8_t id;								/**< Identifier to retrieve (optional) */
};

/**
 * Cerberus protocol get component firmware manifest ID response format with a version identifier
 */
struct cerberus_protocol_get_cfm_id_version_response {
	struct cerberus_protocol_header header;	/**< Message header */
	uint8_t valid;							/**< Indication if the CFM is valid */
	uint32_t version;						/**< CFM version ID */
};

/**
 * Cerberus protocol get component firmware manifest ID response format with a platform identifier
 */
struct cerberus_protocol_get_cfm_id_platform_response {
	struct cerberus_protocol_header header;	/**< Message header */
	uint8_t valid;							/**< Indication if the CFM is valid */
	uint8_t platform;						/**< First byte of the ASCII CFM platform ID */
};


/**
 * Get the total response length for a get component firmware manifest ID response message.
 *
 * @param len Length of the platform id string including null terminator
 */
#define	cerberus_protocol_get_cfm_id_platform_response_length(len)  \
	(len + sizeof (struct cerberus_protocol_get_cfm_id_platform_response) - sizeof (uint8_t))

/**
 * Maximum amount of component firmware manifest platform ID data that can be returned
 *
 * @param req The command request structure containing the message.
 */
#define	CERBERUS_PROTOCOL_MAX_CFM_ID_PLATFORM(req)  \
	((req->max_response - sizeof (struct cerberus_protocol_get_cfm_id_platform_response)) + \
		sizeof (uint8_t))

/**
 * Cerberus protocol prepare component firmware manifest request format
 */
struct cerberus_protocol_prepare_cfm_update {
	struct cerberus_protocol_header header;	/**< Message header */
	uint32_t total_size;					/**< Total expected size of the update */
};

/**
 * Cerberus protocol update component firmware manifest request format
 */
struct cerberus_protocol_cfm_update {
	struct cerberus_protocol_header header;	/**< Message header */
	uint8_t payload;						/**< First byte of the variable CFM data */
};


/**
 * Get the amount of payload data in a CFM update message.
 *
 * @param req The command request structure containing the message.
 */
#define	cerberus_protocol_cfm_update_length(req)    \
	((req->length - sizeof (struct cerberus_protocol_cfm_update)) + sizeof (uint8_t))

/**
 * Cerberus protocol activate component firmware manifest request format
 */
struct cerberus_protocol_complete_cfm_update {
	struct cerberus_protocol_header header;	/**< Message header */
	uint8_t activation;						/**< Manifest activation control */
};

/**
 * Cerberus protocol get component firmware manifest component IDs request format
 */
struct cerberus_protocol_get_cfm_component_ids {
	struct cerberus_protocol_header header;	/**< Message header */
	uint8_t region;							/**< Manifest region to query */
	uint32_t offset;						/**< Offset in the total list for  */
};

/**
 * Cerberus protocol get component firmware manifest component IDs response format
 */
struct cerberus_protocol_get_cfm_component_ids_response {
	struct cerberus_protocol_header header;	/**< Message header */
	uint8_t valid;							/**< Indication if the CFM is valid */
	uint32_t version;						/**< CFM version identifier */
};

/**
 * Get the buffer containing the retrieved component IDs
 */
#define	cerberus_protocol_cfm_component_ids(resp)	(((uint8_t*) resp) + sizeof (*resp))

/**
 * Get the total message length for a get CFM component IDs response message.
 *
 * @param len Length of the component data.
 */
#define	cerberus_protocol_get_cfm_component_ids_response_length(len)    \
	(len + sizeof (struct cerberus_protocol_get_cfm_component_ids_response))

/**
 * Maximum amount of component ID data that can be returned in a single request
 *
 * @param req The command request structure containing the message.
 */
#define	CERBERUS_PROTOCOL_MAX_COMPONENT_IDS(req)    \
	((req)->max_response - sizeof (struct cerberus_protocol_get_cfm_component_ids_response))

/**
 * Cerberus protocol get platform configuration data ID request format
 */
struct cerberus_protocol_get_pcd_id {
	struct cerberus_protocol_header header;	/**< Message header */
	uint8_t id;								/**< Identifier to retrieve (optional) */
};

/**
 * Cerberus protocol get platform configuration data ID response format with a version identifier
 */
struct cerberus_protocol_get_pcd_id_version_response {
	struct cerberus_protocol_header header;	/**< Message header */
	uint8_t valid;							/**< Indication if the PCD is valid */
	uint32_t version;						/**< PCD version ID */
};

/**
 * Cerberus protocol get platform configuration data ID response format with a platform identifier
 */
struct cerberus_protocol_get_pcd_id_platform_response {
	struct cerberus_protocol_header header;	/**< Message header */
	uint8_t valid;							/**< Indication if the PCD is valid */
	uint8_t platform;						/**< First byte of the ASCII PCD platform ID */
};


/**
 * Get the total response length for a get platform configuration data ID response message.
 *
 * @param len Length of the platform id string including null terminator
 */
#define	cerberus_protocol_get_pcd_id_platform_response_length(len)  \
	(len + sizeof (struct cerberus_protocol_get_pcd_id_platform_response) - sizeof (uint8_t))

/**
 * Maximum amount of platform configuration data platform ID data that can be returned
 *
 * @param req The command request structure containing the message.
 */
#define	CERBERUS_PROTOCOL_MAX_PCD_ID_PLATFORM(req)  \
	((req->max_response - sizeof (struct cerberus_protocol_get_pcd_id_platform_response)) + \
		sizeof (uint8_t))

/**
 * Cerberus protocol prepare platform configuration data request format
 */
struct cerberus_protocol_prepare_pcd_update {
	struct cerberus_protocol_header header;	/**< Message header */
	uint32_t total_size;					/**< Total expected size of the update */
};

/**
 * Cerberus protocol update platform configuration data request format
 */
struct cerberus_protocol_pcd_update {
	struct cerberus_protocol_header header;	/**< Message header */
	uint8_t payload;						/**< First byte of the variable CFM data */
};


/**
 * Get the amount of payload data in a PCD update message.
 *
 * @param req The command request structure containing the message.
 */
#define	cerberus_protocol_pcd_update_length(req)    \
	((req->length - sizeof (struct cerberus_protocol_pcd_update)) + sizeof (uint8_t))

/**
 * Cerberus protocol activate platform configuration data request format
 */
struct cerberus_protocol_complete_pcd_update {
	struct cerberus_protocol_header header;	/**< Message header */
	uint8_t activation;						/**< Manifest activation control */
};


/**
 * Minimum required length of the activate platform configuration data request.  This length
 * excludes optional payload bytes.
 */
#define	CERBERUS_PROTOCOL_COMPLETE_PCD_UPDATE_MIN_LENGTH     \
	(sizeof (struct cerberus_protocol_complete_pcd_update) - sizeof (uint8_t))

/**
 * Cerberus protocol update status request format
 */
struct cerberus_protocol_update_status {
	struct cerberus_protocol_header header;	/**< Message header */
	uint8_t update_type;					/**< Update type to query for status */
	uint8_t port_id;						/**< Port identifier, if applicable */
};

/**
 * Cerberus protocol update status response format
 */
struct cerberus_protocol_update_status_response {
	struct cerberus_protocol_header header;	/**< Message header */
	uint32_t update_status;					/**< Status of the requested update */
};

/**
 * Cerberus protocol get platform configuration data component IDs request format
 */
struct cerberus_protocol_get_pcd_component_ids {
	struct cerberus_protocol_header header;	/**< Message header */
	uint32_t offset;						/**< Offset in the total list of PCD components */
};

/**
 * Cerberus protocol get platform configuration data component IDs response format
 */
struct cerberus_protocol_get_pcd_component_ids_response {
	struct cerberus_protocol_header header;	/**< Message header */
	uint8_t valid;							/**< Indication if the PCD is valid */
	uint32_t version;						/**< PCD version identifier */
};

/**
 * Get the buffer containing the retrieved component IDs
 *
 * @param resp The commmand response structure containing the message.
 */
#define	cerberus_protocol_pcd_component_ids(resp)	(((uint8_t*) resp) + sizeof (*resp))

/**
 * Get the total message length for a get PCD component IDs response message.
 *
 * @param len Length of the component data.
 */
#define	cerberus_protocol_get_pcd_component_ids_response_length(len)    \
	(len + sizeof (struct cerberus_protocol_get_pcd_component_ids_response))

/**
 * Maximum amount of component ID data that can be returned in a single request
 *
 * @param req The command request structure containing the message.
 */
#define	CERBERUS_PROTOCOL_MAX_PCD_COMPONENT_IDS(req)    \
	((req)->max_response - sizeof (struct cerberus_protocol_get_pcd_component_ids_response))

/**
 * Cerberus protocol get platform configuration data component instance info request format
 */
struct cerberus_protocol_get_pcd_component_instance_info {
	struct cerberus_protocol_header header;	/**< Message header */
	uint32_t component_id;					/**< Component ID for instances requested */
};

/**
 * Cerberus protocol get platform configuration data component instance info response format
 */
struct cerberus_protocol_get_pcd_component_instance_info_response {
	struct cerberus_protocol_header header;	/**< Message header */
	uint8_t count;							/**< Number of Instance info insatances returned */
};

/**
 * Get the buffer containing the retrieved component instance info
 *
 * @param resp The commmand response structure containing the message.
 */
#define	cerberus_protocol_pcd_component_instance_info(resp)	(((uint8_t*) resp) + sizeof (*resp))

/**
 * Get the total message length for a get PCD component instance info response message.
 *
 * @param len Length of the instance info data.
 */
#define	cerberus_protocol_get_pcd_component_instance_info_response_length(len)    \
	(len + sizeof (struct cerberus_protocol_get_pcd_component_instance_info_response))

/**
 * Maximum amount of component instance info data that can be returned in a single request
 *
 * @param req The command request structure containing the message.
 */
#define	cerberus_protocol_max_pcd_component_instance_info(req)    \
	((req)->max_response - \
	sizeof (struct cerberus_protocol_get_pcd_component_instance_info_response))

/**
 * Cerberus protocol get extended update status request format
 */
struct cerberus_protocol_extended_update_status {
	struct cerberus_protocol_header header;	/**< Message header */
	uint8_t update_type;					/**< Update type */
	uint8_t port_id;						/**< Port ID */
};

/**
 * Cerberus protocol get extended update status response format
 */
struct cerberus_protocol_extended_update_status_response {
	struct cerberus_protocol_header header;	/**< Message header */
	uint32_t update_status;					/**< Update status */
	uint32_t remaining_len;					/**< Number of bytes expected to still be sent */
};

/**
 * Cerberus protocol get configuration IDs request format
 */
struct cerberus_protocol_get_configuration_ids {
	struct cerberus_protocol_header header;	/**< Message header */
	uint8_t nonce[32];						/**< Random nonce for freshness */
};

/**
 * Cerberus protocol get configuration IDs response format
 */
struct cerberus_protocol_get_configuration_ids_response {
	struct cerberus_protocol_header header;	/**< Message header */
	uint8_t nonce[32];						/**< Random nonce for freshness */
	uint8_t pfm_count;						/**< Number of PFM IDs reported */
	uint8_t cfm_count;						/**< Number of CFM IDs reported */
	uint32_t version_id;					/**< First version ID in the variable list */
};


/**
 * Get a pointer to the first platform ID in a get configuration IDs response
 */
#define cerberus_protocol_configuration_ids_get_platform_ids(resp)  \
	(((uint8_t*) resp) + sizeof (*resp) + (sizeof (uint32_t) * (resp->pfm_count + resp->cfm_count)))
#pragma pack(pop)


int cerberus_protocol_generate_get_certificate_digest_request (uint8_t slot_num, uint8_t key_alg,
	uint8_t *buf, size_t buf_len);
int cerberus_protocol_generate_get_certificate_request (uint8_t slot_num, uint8_t cert_num,
	uint8_t *buf, size_t buf_len, uint16_t offset, uint16_t length);
int cerberus_protocol_generate_challenge_request (const struct rng_engine *rng, uint8_t eid,
	uint8_t slot_num, uint8_t *buf, size_t buf_len);

int cerberus_protocol_generate_get_device_capabilities_request (struct device_manager *device_mgr,
	uint8_t *buf, size_t buf_len);

int cerberus_protocol_cfm_update_init (const struct manifest_cmd_interface *cfm_interface,
	struct cmd_interface_msg *request);
int cerberus_protocol_cfm_update (const struct manifest_cmd_interface *cfm_interface,
	struct cmd_interface_msg *request);
int cerberus_protocol_cfm_update_complete (const struct manifest_cmd_interface *cfm_interface,
	struct cmd_interface_msg *request);

int cerberus_protocol_get_cfm_id (const struct cfm_manager *cfm_mgr,
	struct cmd_interface_msg *request);
int cerberus_protocol_get_cfm_component_ids (const struct cfm_manager *cfm_mgr,
	struct cmd_interface_msg *request);

int cerberus_protocol_pcd_update_init (const struct manifest_cmd_interface *pcd_interface,
	struct cmd_interface_msg *request);
int cerberus_protocol_pcd_update (const struct manifest_cmd_interface *pcd_interface,
	struct cmd_interface_msg *request);
int cerberus_protocol_pcd_update_complete (const struct manifest_cmd_interface *pcd_interface,
	struct cmd_interface_msg *request);

int cerberus_protocol_get_pcd_id (const struct pcd_manager *pcd_mgr,
	struct cmd_interface_msg *request);
int cerberus_protocol_get_pcd_component_ids (const struct pcd_manager *pcd_mgr,
	struct cmd_interface_msg *request);
int cerberus_protocol_get_pcd_component_instance_info (struct device_manager *dev_mgr,
	struct cmd_interface_msg *request);

int cerberus_protocol_get_fw_update_status (const struct firmware_update_control *control,
	struct cerberus_protocol_update_status_response *rsp);
int cerberus_protocol_get_pfm_update_status (const struct manifest_cmd_interface *const pfm_cmd[],
	uint8_t num_ports, struct cmd_interface_msg *request);
int cerberus_protocol_get_cfm_update_status (const struct manifest_cmd_interface *cfm_interface,
	struct cmd_interface_msg *request);
int cerberus_protocol_get_pcd_update_status (const struct manifest_cmd_interface *pcd_interface,
	struct cmd_interface_msg *request);
int cerberus_protocol_get_host_next_verification_status (
	const struct host_cmd_interface *const host[], uint8_t num_ports,
	struct cmd_interface_msg *request);
int cerberus_protocol_get_recovery_image_update_status (
	const struct recovery_image_cmd_interface *recovery_0,
	const struct recovery_image_cmd_interface *recovery_1, struct cmd_interface_msg *request);
int cerberus_protocol_get_reset_config_status (const struct cmd_background *background,
	struct cerberus_protocol_update_status_response *rsp);
int cerberus_protocol_get_host_flash_config_status (const struct host_cmd_interface *const host[],
	uint8_t num_ports, struct cmd_interface_msg *request);
int cerberus_protocol_get_update_status (const struct firmware_update_control *control,
	uint8_t num_ports, const struct manifest_cmd_interface *const pfm_cmd[],
	const struct manifest_cmd_interface *cfm, const struct manifest_cmd_interface *pcd,
	const struct host_cmd_interface *const host[],
	const struct recovery_image_cmd_interface *recovery_0,
	const struct recovery_image_cmd_interface *recovery_1, const struct cmd_background *background,
	struct cmd_interface_msg *request);

int cerberus_protocol_get_extended_fw_update_status (const struct firmware_update_control *control,
	struct cerberus_protocol_extended_update_status_response *rsp);
int cerberus_protocol_get_extended_recovery_image_update_status (
	struct recovery_image_manager *manager_0, struct recovery_image_manager *manager_1,
	const struct recovery_image_cmd_interface *cmd_0,
	const struct recovery_image_cmd_interface *cmd_1, uint8_t port, uint32_t *update_status,
	uint32_t *rem_len);
int cerberus_protocol_get_extended_update_status (const struct firmware_update_control *control,
	struct recovery_image_manager *recovery_manager_0,
	struct recovery_image_manager *recovery_manager_1,
	const struct recovery_image_cmd_interface *recovery_cmd_0,
	const struct recovery_image_cmd_interface *recovery_cmd_1, struct cmd_interface_msg *request);

int cerberus_protocol_process_certificate_digest_response (struct cmd_interface_msg *response);
int cerberus_protocol_process_certificate_response (struct cmd_interface_msg *response);
int cerberus_protocol_process_challenge_response (struct cmd_interface_msg *response);

int cerberus_protocol_process_device_capabilities_response (struct device_manager *device_mgr,
	struct cmd_interface_msg *response);

/* Private functions for internal use */
int cerberus_protocol_get_manifest_id_version (const struct manifest *manifest,
	struct cmd_interface_msg *request);
int cerberus_protocol_get_manifest_id_platform (const struct manifest *manifest,
	struct cmd_interface_msg *request);


#endif	/* CERBERUS_PROTOCOL_MASTER_COMMANDS_H_ */
