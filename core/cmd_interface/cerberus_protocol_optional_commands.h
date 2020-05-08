// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_PROTOCOL_OPTIONAL_COMMANDS_H_
#define CERBERUS_PROTOCOL_OPTIONAL_COMMANDS_H_

#include <stdint.h>
#include <stdbool.h>
#include "cmd_interface/cmd_authorization.h"
#include "cmd_interface/cmd_background.h"
#include "cmd_interface/cmd_interface.h"
#include "attestation/pcr_store.h"
#include "attestation/attestation.h"
#include "crypto/hash.h"
#include "host_fw/host_processor.h"
#include "host_fw/host_control.h"
#include "firmware/firmware_update_control.h"
#include "manifest/pfm/pfm_manager.h"
#include "manifest/manifest_cmd_interface.h"
#include "mctp/mctp_protocol.h"
#include "recovery/recovery_image_cmd_interface.h"
#include "recovery/recovery_image_manager.h"


/**
 * Identifier for the type of system log.
 */
enum {
	CERBERUS_PROTOCOL_DEBUG_LOG = 1,						/**< Debug log type. */
	CERBERUS_PROTOCOL_TCG_LOG,								/**< TCG log type. */
	CERBERUS_PROTOCOL_TAMPER_LOG							/**< Tamper log type. */
};

/**
 * Identifier for the type of key being exchanged.
 */
enum {
	CERBERUS_PROTOCOL_SESSION_KEY = 0,						/**< Exchange session encryption key */
	CERBERUS_PROTOCOL_PAIRED_KEY_HMAC,						/**< Exchange an HMAC paired key */
	CERBERUS_PROTOCOL_PAIRED_KEY_ECC						/**< Exchange an ECC paired key */
};

/**
 * Indentifier for the reset state of the host processor.
 */
enum {
	CERBERUS_PROTOCOL_HOST_RUNNING = 0,						/**< The host is not in reset */
	CERBERUS_PROTOCOL_HOST_HELD_IN_RESET,					/**< The host is being held in reset */
	CERBERUS_PROTOCOL_HOST_IN_RESET							/**< The hosh is not being held in reset, but is not running */
};

/**
 * Identifier for the type of configuration reset to execute.
 */
enum {
	CERBERUS_PROTOCOL_REVERT_BYPASS = 0,					/**< Reset device to the unprotected state */
	CERBERUS_PROTOCOL_FACTORY_RESET							/**< Restore factory default configuration */
};

/**
 * Identifier for the unsealing HMAC algorithm.
 */
enum {
	CERBERUS_PROTOCOL_UNSEAL_HMAC_SHA256 = 0				/**< Unseal HMAC using SHA-256 */
};

/**
 * Identifier for the unsealing seed type.
 */
enum {
	CERBERUS_PROTOCOL_UNSEAL_SEED_RSA = 0,					/**< Unseal seed is RSA encrypted */
	CERBERUS_PROTOCOL_UNSEAL_SEED_ECDH						/**< Unseal seed uses ECDH */
};

/**
 * Identifier for unsealing RSA parameters.
 */
enum {
	CERBERUS_PROTOCOL_UNSEAL_RSA_PKCS15 = 0,				/**< Seed is encrypted with PKCS 1.5 padding */
	CERBERUS_PROTOCOL_UNSEAL_RSA_OAEP_SHA1,					/**< Seed is encrypted with OAEP-SHA1 padding */
	CERBERUS_PROTOCOL_UNSEAL_RSA_OAEP_SHA256,				/**< Seed is encrypted with OAEP-SHA256 padding */
};

/**
 * Maximum number of PMRs that can be used for unsealing.
 *
 *
 */
#define	CERBERUS_PROTOCOL_MAX_PMR			5


#pragma pack(push, 1)
/**
 * Cerberus protocol prepare platform firmware manifest request format
 */
struct cerberus_protocol_prepare_pfm_update {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t port_id;										/**< Port ID */
	uint32_t size;											/**< Update size */
};

/**
 * Cerberus protocol platform firmware manifest update request format
 */
struct cerberus_protocol_pfm_update {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t port_id;										/**< Port ID */
	uint8_t payload;										/**< First byte of the variable PFM data */
};

/**
 * Get the amount of payload data in a PFM update message.
 *
 * @param req The command request structure containing the message.
 */
#define	cerberus_protocol_pfm_update_length(req)	\
	((req->length - sizeof (struct cerberus_protocol_pfm_update)) + sizeof (uint8_t))

/**
 * Cerberus protocol activate platform firmware manifest request format
 */
struct cerberus_protocol_complete_pfm_update {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t port_id;										/**< Port ID */
	uint8_t activation;										/**< 0 for after reboot, 1 to activate immediately */
};

/**
 * Cerberus protocol get platform firmware manifest ID request format
 */
struct cerberus_protocol_get_pfm_id {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t port_id;										/**< Port ID */
	uint8_t region;											/**< 0 for active, 1 for staging */
	uint8_t id;												/**< Identifier to retrieve (optional) */
};

/**
 * Cerberus protocol get platform firmware manifest ID response format with a version identifier
 */
struct cerberus_protocol_get_pfm_id_version_response {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t valid;											/**< Port contains valid PFM */
	uint32_t version;										/**< PFM version ID */
};

/**
 * Cerberus protocol get platform firmware manifest ID response format with a platform identifier
 */
struct cerberus_protocol_get_pfm_id_platform_response {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t valid;											/**< Port contains valid PFM */
	uint8_t platform;										/**< First byte of the ASCII platform ID */
};

/**
 * Cerberus protocol get platform firmware manifest supported FW request format
 */
struct cerberus_protocol_get_pfm_supported_fw {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t port_id;										/**< Port ID */
	uint8_t region;											/**< 0 for active, 1 for staging */
	uint32_t offset;										/**< Offset to start response at */
};

/**
 * Cerberus protocol get platform firmware manifest supported FW response format
 */
struct cerberus_protocol_get_pfm_supported_fw_response {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t valid;											/**< Port contains valid PFM */
	uint32_t version;										/**< PFM version identifier */
};

/**
 * Get the buffer containing the support FW versions
 */
#define	cerberus_protocol_pfm_supported_fw(resp)	(((uint8_t*) resp) + sizeof (*resp))

/**
 * Get the total message length for a get PFM support FW versions response message.
 *
 * @param len Length of the version data.
 */
#define	cerberus_protocol_get_pfm_supported_fw_response_length(len)	\
	(len + sizeof (struct cerberus_protocol_get_pfm_supported_fw_response))

/**
 * Maximum amount of supported FW version data that can be returned in a single request
 *
 * @param req The command request structure containing the message.
 */
#define	CERBERUS_PROTOCOL_MAX_PFM_VERSIONS(req)	\
	(req->max_response - sizeof (struct cerberus_protocol_get_pfm_supported_fw_response))

/**
 * Cerberus protocol recover firmware request format
 */
struct cerberus_protocol_recover_firmware {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t port_id;										/**< Port ID for recovery */
	uint8_t recovery_img;									/**< Recovery image ID */
};

/**
 * Cerberus protocol prepare a host recovery image update request format
 */
struct cerberus_protocol_prepare_recovery_image_update {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t port_id;										/**< Port ID */
	uint32_t size;											/**< Update size */
};

/**
 * Cerberus protocol host recovery image update request format
 */
struct cerberus_protocol_recovery_image_update {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t port_id;										/**< Port ID */
	uint8_t payload;										/**< First byte of the variable data */
};

/**
 * Get the amount of payload data in a recovery image update message.
 *
 * @param req The command request structure containing the message.
 */
#define	cerberus_protocol_recovery_image_update_length(req)	\
	((req->length - sizeof (struct cerberus_protocol_recovery_image_update)) + sizeof (uint8_t))

/**
 * Cerberus protocol host recovery image activate update request format
 */
struct cerberus_protocol_complete_recovery_image_update {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t port_id;										/**< Port ID */
};

/**
 * Cerberus protocol get host recovery image ID request format
 */
struct cerberus_protocol_get_recovery_image_id {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t port_id;										/**< Port ID */
	uint8_t id;												/**< Identifier to retrieve (optional) */
};

/**
 * Cerberus protocol get host recovery image ID response format with a version identifier
 */
struct cerberus_protocol_get_recovery_image_id_version_response {
	struct cerberus_protocol_header header;					/**< Message header */
	char version[32];										/**< Version ID */
};

/**
 * Cerberus protocol get host recovery image ID response format with a platform identifier
 */
struct cerberus_protocol_get_recovery_image_id_platform_response {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t platform;										/**< First byte of the ASCII platform ID */
};

/**
 * Cerberus protocol get host reset status request format
 */
struct cerberus_protocol_get_host_state {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t port_id;										/**< Port ID */
};

/**
 * Cerberus protocol get host reset status response format
 */
struct cerberus_protocol_get_host_state_response {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t reset_status;									/**< Host reset status */
};

/**
 * Cerberus protorol get platform measurement register request format
 */
struct cerberus_protocol_pmr {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t measurement_number;								/**< PMR to query */
	uint8_t nonce[32];										/**< Requestor freshness seed */
};

/**
 * Cerberus protocol get platform measurement register response format
 */
struct cerberus_protocol_pmr_response {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t nonce[32];										/**< Responder freshness seed */
	uint8_t pmr_length;										/**< Length of the measureent */
	uint8_t measurement;									/**< First byte of the variable length measurement */
};

/**
 * Get the buffer containing the PMR response signature.
 *
 * @param resp Pointer to a PMR response message.
 */
#define	cerberus_protocol_pmr_get_signature(resp)	((&((resp)->measurement)) + (resp)->pmr_length)

/**
 * Cerberus protocol update platform measurement register request format
 */
struct cerberus_protocol_update_pmr {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t measurement_number;								/**< Index for the PMR to update */
	uint8_t measurement_ext;								/**< First byte of the measurement to use for the update */
};

/**
 * Get the amount of measurement data in an update PMR message.
 *
 * @param req The command request structure containing the message.
 */
#define	cerberus_protocol_update_pmr_measurement_length(req)	\
	((req->length - sizeof (struct cerberus_protocol_update_pmr)) + sizeof (uint8_t))

/**
 * Cerberus protocol key exchange request format
 */
struct cerberus_protocol_key_exchange {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t key_type;										/**< Type of key being exchanged */
	uint8_t key;											/**< First byte of variable key data */
};

/**
 * Cerberus protocol get log info request format
 */
struct cerberus_protocol_get_log_info {
	struct cerberus_protocol_header header;					/**< Message header */
};

/**
 * Cerberus protocol get log info response format
 */
struct cerberus_protocol_get_log_info_response {
	struct cerberus_protocol_header header;					/**< Message header */
	uint32_t debug_log_length;								/**< Length of the debug log */
	uint32_t attestation_log_length;						/**< Length of the attestation log */
	uint32_t tamper_log_length;								/**< Length of the tamper log */
};

/**
 * Cerberus protocol get log request format
 */
struct cerberus_protocol_get_log {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t log_type;										/**< Log indentifier to read */
	uint32_t offset;										/**< Offset to start reding the log */
};

/**
 * Cerberus protocol get log response format
 */
struct cerberus_protocol_get_log_response {
	struct cerberus_protocol_header header;					/**< Message header */
};

/**
 * Get the buffer containing the retrieved log data
 */
#define	cerberus_protocol_log_data(resp)	(((uint8_t*) resp) + sizeof (*resp))

/**
 * Get the total message length for a get log response message.
 *
 * @param log_len Length of the log data.
 */
#define	cerberus_protocol_get_log_response_length(log_len)	\
	(log_len + sizeof (struct cerberus_protocol_get_log_response))

/**
 * Maximum amount of log data that can be returned in a single request
 *
 * @param req The command request structure containing the message.
 */
#define	CERBERUS_PROTOCOL_MAX_LOG_DATA(req)	\
	(req->max_response - sizeof (struct cerberus_protocol_get_log_response))

/**
 * Cerberus protocol clear log request format
 */
struct cerberus_protocol_clear_log {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t log_type;										/**< Log to clear */
};

/**
 * Cerberus protocol get attestation data request format
 */
struct cerberus_protocol_get_attestation_data {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t pmr;											/**< PMR index for the requested data */
	uint8_t entry;											/**< Entry index for the requested data */
	uint32_t offset;										/**< Offset in the data */
};

/**
 * Cerberus protocol get attestation data request format
 */
struct cerberus_protocol_get_attestation_data_response {
	struct cerberus_protocol_header header;					/**< Message header */
};

/**
 * Get the buffer containing the retrieved raw attestation data
 */
#define	cerberus_protocol_attestation_data(resp)	(((uint8_t*) resp) + sizeof (*resp))

/**
 * Get the total message length for a get attestation data response message.
 *
 * @param len Length of the log data.
 */
#define	cerberus_protocol_get_attestation_data_response_length(len)	\
	(len + sizeof (struct cerberus_protocol_get_attestation_data_response))

/**
 * Maximum amount of attestation data that can be returned in a single request
 *
 * @param req The command request structure containing the message.
 */
#define	CERBERUS_PROTOCOL_MAX_ATTESTATION_DATA(req)	\
	(req->max_response - sizeof (struct cerberus_protocol_get_attestation_data_response))

/**
 * Cerberus protocol prepare firmware update request format
 */
struct cerberus_protocol_prepare_fw_update {
	struct cerberus_protocol_header header;					/**< Message header */
	uint32_t total_size;									/**< Total update size */
};

/**
 * Cerberus protocol firmware update request format
 */
struct cerberus_protocol_fw_update {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t payload;										/**< First byte of the variable data */
};

/**
 * Get the amount of payload data in a FW update message.
 *
 * @param req The command request structure containing the message.
 */
#define	cerberus_protocol_fw_update_length(req)	\
	((req->length - sizeof (struct cerberus_protocol_fw_update)) + sizeof (uint8_t))

/**
 * Cerberus protocol activate firmware update request format
 */
struct cerberus_protocol_complete_fw_update {
	struct cerberus_protocol_header header;					/**< Message header */
};

/**
 * Cerberus protocol reset configuration request format
 */
struct cerberus_protocol_reset_config {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t type;											/**< The type of reset opeartion to perform */
};

/**
 * Get the buffer containing the authorization token for a reset operation.  This works with both
 * reset configuration request and response messages.
 */
#define	cerberus_protocol_reset_authorization(msg)	(((uint8_t*) msg) + sizeof (*msg))

/**
 * Get the amount of authorization token data in a reset configuration message.
 *
 * @param req The command request structure containing the message.
 */
#define	cerberus_protocol_reset_authorization_length(req)	\
	(req->length - sizeof (struct cerberus_protocol_reset_config))

/**
 * Cerberus protocol reset configuration response format
 */
struct cerberus_protocol_reset_config_response {
	struct cerberus_protocol_header header;					/**< Message header */
};

/**
 * Get the total message length for a reset configuration response message.
 *
 * @param auth_len Length of the authorization data.
 */
#define	cerberus_protocol_get_reset_config_response_length(auth_len)	\
	(auth_len + sizeof (struct cerberus_protocol_reset_config_response))

/**
 * Maximum amount of authorization data that can be returned for a reset configuration request.
 *
 * @param req The command request structure containing the message.
 */
#define	CERBERUS_PROTOCOL_MAX_AUTHORIZATION_DATA(req)	\
	(req->max_response - sizeof (struct cerberus_protocol_reset_config_response))

/**
 * Cerberus protocol message unseal request format
 */
struct cerberus_protocol_message_unseal {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t seed_type:2;									/**< Type of seed used for unsealing */
	uint8_t hmac_type:3;									/**< Type of HMAC used for unsealing */
	uint8_t reserved:3;										/**< Unused */
	union {
		struct {
			uint8_t padding:3;								/**< RSA encryption padding scheme */
			uint8_t reserved:5;								/**< Unused */
		} rsa;
		struct {
			uint8_t reserved;								/**< Unused. */
		} ecdh;
	} seed_params;											/**< Additional parameters for the seed */
	uint16_t seed_length;									/**< Length of the unsealing seed */
	uint8_t seed;											/**< First byte of the unsealing seed */
};

/**
 * PMRs used for unsealing a message.
 */
struct cerberus_protocol_unseal_pmrs {
	uint8_t pmr[CERBERUS_PROTOCOL_MAX_PMR][64];				/**< PMRs used for sealing */
};

/**
 * Get the pointer to the ciphertext length entry
 */
#define	cerberus_protocol_unseal_ciphertext_length_ptr(req) \
	(((uint8_t*) req) + sizeof (*req) + req->seed_length - sizeof (req->seed))

/**
 * Get the ciphertext length in an unseal request message
 */
#define	cerberus_protocol_unseal_ciphertext_length(req)	\
	*((uint16_t*) cerberus_protocol_unseal_ciphertext_length_ptr (req))

/**
 * Get the buffer containing the ciphertext from an unseal request message
 */
#define	cerberus_protocol_unseal_ciphertext(req) \
	(cerberus_protocol_unseal_ciphertext_length_ptr (req) + sizeof (uint16_t))

/**
 * Get the pointer to the HMAC length entry
 */
#define	cerberus_protocol_unseal_hmac_length_ptr(req) \
	(cerberus_protocol_unseal_ciphertext (req) + cerberus_protocol_unseal_ciphertext_length (req))

/**
 * Get the HMAC length in an unseal request message
 */
#define	cerberus_protocol_unseal_hmac_length(req)	\
	*((uint16_t*) cerberus_protocol_unseal_hmac_length_ptr (req))

/**
 * Get the buffer containing the HMAC from an unseal request message
 */
#define	cerberus_protocol_unseal_hmac(req) \
	(cerberus_protocol_unseal_hmac_length_ptr (req) + sizeof (uint16_t))

/**
 * Get the list of PMRs to use for unsealing.  This will returned as a pointer to
 * struct cerberus_protocol_unseal_pmrs.
 */
#define	cerberus_protocol_get_unseal_pmr_sealing(req) \
	((const struct cerberus_protocol_unseal_pmrs*) (cerberus_protocol_unseal_hmac (req) + cerberus_protocol_unseal_hmac_length (req)))

/**
 * Cerberus protocol message unseal result request format
 */
struct cerberus_protocol_message_unseal_result {
	struct cerberus_protocol_header header;					/**< Message header */
};

/**
 * Cerberus protocol message unseal result request format
 */
struct cerberus_protocol_message_unseal_result_response {
	struct cerberus_protocol_header header;					/**< Message header */
	uint32_t unseal_status;									/**< Status of the unseal operation */
};

/**
 * Cerberus protocol message unseal result request format
 */
struct cerberus_protocol_message_unseal_result_completed_response {
	struct cerberus_protocol_header header;					/**< Message header */
	uint32_t unseal_status;									/**< Status of the unseal operation */
	uint16_t key_length;									/**< Length of the unsealed key */
	uint8_t key;											/**< First byte of the variable length key */
};

/**
 * Get the total message length for an unseal result response message with key data.
 *
 * @param len Length of the key data.
 */
#define	cerberus_protocol_get_unseal_response_length(len)	\
	((len + sizeof (struct cerberus_protocol_message_unseal_result_completed_response)) - sizeof (uint8_t))

/**
 * Maximum amount of key data that can be returned from an unseal request
 *
 * @param req The command request structure containing the message.
 */
#define	CERBERUS_PROTOCOL_MAX_UNSEAL_KEY_DATA(req)	\
	((req->max_response - sizeof (struct cerberus_protocol_message_unseal_result_completed_response)) + sizeof (uint8_t))
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

int cerberus_protocol_get_pfm_id (struct pfm_manager *pfm_mgr_0, struct pfm_manager *pfm_mgr_1,
	struct cmd_interface_request *request);
int cerberus_protocol_get_pfm_fw (struct manifest_cmd_interface *pfm_0,
	struct manifest_cmd_interface *pfm_1, struct pfm_manager *pfm_mgr_0,
	struct pfm_manager *pfm_mgr_1, struct cmd_interface_request *request);

struct manifest_cmd_interface* cerberus_protocol_get_pfm_cmd_interface (
	struct manifest_cmd_interface *pfm_0, struct manifest_cmd_interface *pfm_1, uint8_t port);

int cerberus_protocol_pfm_update_init (struct manifest_cmd_interface *pfm_0,
	struct manifest_cmd_interface *pfm_1, struct cmd_interface_request *request);
int cerberus_protocol_pfm_update (struct manifest_cmd_interface *pfm_0,
	struct manifest_cmd_interface *pfm_1, struct cmd_interface_request *request);
int cerberus_protocol_pfm_update_complete (struct manifest_cmd_interface *pfm_0,
	struct manifest_cmd_interface *pfm_1, struct cmd_interface_request *request);

int cerberus_protocol_get_host_reset_status (struct host_control *host_0_ctrl,
	struct host_control *host_1_ctrl, struct cmd_interface_request *request);

int cerberus_protocol_unseal_message (struct cmd_background *background,
	struct cmd_interface_request *request);
int cerberus_protocol_unseal_message_result (struct cmd_background *background,
	struct cmd_interface_request *request);

int cerberus_protocol_reset_config (struct cmd_authorization *cmd_auth,
	struct cmd_background *background, struct cmd_interface_request *request);

struct recovery_image_cmd_interface* cerberus_protocol_get_recovery_image_cmd_interface (
	struct recovery_image_cmd_interface *recovery_0,
	struct recovery_image_cmd_interface *recovery_1, uint8_t port);
struct recovery_image_manager* cerberus_protocol_get_recovery_image_manager (
	struct recovery_image_manager *recovery_manager_0,
	struct recovery_image_manager *recovery_manager_1, uint8_t port);

int cerberus_protocol_prepare_recovery_image ( struct recovery_image_cmd_interface *recovery_0,
	struct recovery_image_cmd_interface *recovery_1, struct cmd_interface_request *request);
int cerberus_protocol_update_recovery_image (struct recovery_image_cmd_interface *recovery_0,
	struct recovery_image_cmd_interface *recovery_1, struct cmd_interface_request *request);
int cerberus_protocol_activate_recovery_image (struct recovery_image_cmd_interface *recovery_0,
	struct recovery_image_cmd_interface *recovery_1, struct cmd_interface_request *request);
int cerberus_protocol_get_recovery_image_id (struct recovery_image_manager *manager_0,
	struct recovery_image_manager *manager_1, struct cmd_interface_request *request);

int cerberus_protocol_get_attestation_data (struct pcr_store *store,
	struct cmd_interface_request *request);


#endif // CERBERUS_PROTOCOL_OPTIONAL_COMMANDS_H_
