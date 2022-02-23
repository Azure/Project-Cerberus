// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_PROTOCOL_OPTIONAL_COMMANDS_H_
#define CERBERUS_PROTOCOL_OPTIONAL_COMMANDS_H_

#include <stdint.h>
#include <stdbool.h>
#include "cmd_interface/cerberus_protocol.h"
#include "cmd_interface/cmd_authorization.h"
#include "cmd_interface/cmd_background.h"
#include "cmd_interface/cmd_interface.h"
#include "cmd_interface/session_manager.h"
#include "attestation/pcr_store.h"
#include "attestation/attestation.h"
#include "crypto/hash.h"
#include "host_fw/host_processor.h"
#include "host_fw/host_control.h"
#include "firmware/firmware_update_control.h"
#include "manifest/pfm/pfm_manager.h"
#include "manifest/manifest_cmd_interface.h"
#include "mctp/mctp_base_protocol.h"
#include "recovery/recovery_image_cmd_interface.h"
#include "recovery/recovery_image_manager.h"


/**
 * Identifier for the type of system log.
 */
enum {
	CERBERUS_PROTOCOL_DEBUG_LOG = 1,						/**< Debug log type. */
	CERBERUS_PROTOCOL_ATTESTATION_LOG,						/**< Attestation log type. */
	CERBERUS_PROTOCOL_TAMPER_LOG,							/**< Tamper log type. */
	CERBERUS_PROTOCOL_TCG_LOG,								/**< TCG formatted log type. */
};

/**
 * Identifier for the type of key being exchanged.
 */
enum {
	CERBERUS_PROTOCOL_SESSION_KEY = 0,						/**< Exchange session encryption key */
	CERBERUS_PROTOCOL_PAIRED_KEY_HMAC,						/**< Exchange an HMAC paired key */
	CERBERUS_PROTOCOL_DELETE_SESSION_KEY,					/**< Delete session key */
};

/**
 * Identifier for the type of HMAC used in a key exchange.
 */
enum {
	CERBERUS_PROTOCOL_HMAC_SHA256 = 0,						/**< HMAC using SHA256 */
	CERBERUS_PROTOCOL_HMAC_SHA384,							/**< HMAC using SHA384 */
	CERBERUS_PROTOCOL_HMAC_SHA512,							/**< HMAC using SHA512 */
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
	CERBERUS_PROTOCOL_FACTORY_RESET,						/**< Restore factory default configuration */
	CERBERUS_PROTOCOL_CLEAR_PCD,							/**< Remove any PCD used by the device. */
	CERBERUS_PROTOCOL_CLEAR_CFM,							/**< Remove any CFM used for component attestation. */
	CERBERUS_PROTOCOL_RESET_INTRUSION,						/**< Clear the device intrusion state. */
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
 * Identifier for unsealing ECDH parameters.
 */
enum {
	CERBERUS_PROTOCOL_UNSEAL_ECDH_RAW = 0,					/**< Seed is the raw ECDH output */
	CERBERUS_PROTOCOL_UNSEAL_ECDH_SHA256,					/**< Seed is the SHA256 hash of the ECDH output */
};


/**
 * Maximum number of PMRs that can be used for unsealing.
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
 * Get the total response length for a get platform firmware manifest ID response message.
 *
 * @param len Length of the platform id string including null terminator
 */
#define	cerberus_protocol_get_pfm_id_platform_response_length(len)	\
	(len + sizeof (struct cerberus_protocol_get_pfm_id_platform_response) - sizeof (uint8_t))

/**
 * Maximum amount of platform firmware manifest platform ID data that can be returned
 *
 * @param req The command request structure containing the message.
 */
#define	CERBERUS_PROTOCOL_MAX_PFM_ID_PLATFORM(req)	\
	((req->max_response - sizeof (struct cerberus_protocol_get_pfm_id_platform_response)) + sizeof (uint8_t))

/**
 * Cerberus protocol get platform firmware manifest supported FW request format.  This is the
 * minimum length of the command and does not include optional arguments.
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
 * Get the length of the firmware ID being queried
 */
#define	cerberus_protocol_get_pfm_supported_fw_id_length(req)	*(((uint8_t*) req) + sizeof (*req))

/**
 * Get the buffer containing the firmware ID string being queried
 */
#define	cerberus_protocol_get_pfm_supported_fw_id(req)	\
	(((char*) req) + sizeof (*req) + sizeof (uint8_t))

/**
 * Get the total length of a supported FW request that includes the option firmware ID.
 */
#define	cerberus_protocol_get_pfm_supported_fw_request_length_with_id(req) \
	(sizeof (*req) + sizeof (uint8_t) + cerberus_protocol_get_pfm_supported_fw_id_length (req))

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
};

/**
 * Get the buffer containing the request data in an exchange request
 *
 * @param req The command request structure containing the message.
 */
#define	cerberus_protocol_key_exchange_data(req)	\
	(((uint8_t*) req) + sizeof (struct cerberus_protocol_key_exchange))

/**
 * Get request data length from a key exchange request.
 *
 * @param req The command request structure containing the message.
 */
#define	cerberus_protocol_key_exchange_data_len(req)	\
	(req->length - sizeof (struct cerberus_protocol_key_exchange))

/**
 * Cerberus protocol key exchange response format
 */
struct cerberus_protocol_key_exchange_response {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t key_type;										/**< Type of key being exchanged */
};

/**
 * Get the buffer containing the response data in an exchange request
 *
 * @param req The command request structure containing the message.
 */
#define	cerberus_protocol_key_exchange_response_data(req)	\
	(((uint8_t*) req) + sizeof (struct cerberus_protocol_key_exchange_response))

/**
 * Cerberus protocol key exchange type 0 request format
 */
struct cerberus_protocol_key_exchange_type_0 {
	struct cerberus_protocol_key_exchange common;			/**< Common request fields between all key exchange requests */
	uint8_t hmac_type;										/**< Type of HMAC to be used in this exchange */
};

/**
 * Get the buffer containing the ephemeral key data in a type 0 key exchange request
 *
 * @param req The command request structure containing the message.
 */
#define	cerberus_protocol_key_exchange_type_0_key_data(req)	\
	(((uint8_t*) req) + sizeof (struct cerberus_protocol_key_exchange_type_0))

/**
 * Get the total message length for a type 0 key exchange request.
 *
 * @param len Length of the key data.
 */
#define	cerberus_protocol_key_exchange_type_0_length(len)	\
	(len + sizeof (struct cerberus_protocol_key_exchange_type_0))

/**
 * Get the key length from a type 0 key exchange request.
 *
 * @param req The command request structure containing the message.
 */
#define	cerberus_protocol_key_exchange_type_0_key_len(req)	\
	(req->length - sizeof (struct cerberus_protocol_key_exchange_type_0))

/**
 * Cerberus protocol key exchange type 0 response format
 */
struct cerberus_protocol_key_exchange_response_type_0 {
	struct cerberus_protocol_key_exchange common;			/**< Common response fields between all key exchange responses */
	uint8_t reserved;										/**< Reserved */
	uint16_t key_len;										/**< Cerberus ephemeral key length */
};

/**
 * Get the buffer containing the ephemeral key data in a type 0 key exchange response
 *
 * @param req The cerberus_protocol_key_exchange_response_type_0 structure containing the message.
 */
#define	cerberus_protocol_key_exchange_type_0_response_key_data(req)	\
	(((uint8_t*) req) + sizeof (struct cerberus_protocol_key_exchange_response_type_0))

/**
 * Maximum key length that can be returned in a single request
 *
 * @param req The command request structure containing the message.
 */
#define	CERBERUS_PROTOCOL_KEY_EXCHANGE_TYPE_0_RESPONSE_MAX_KEY_DATA(req)	\
	(req->max_response - sizeof (struct cerberus_protocol_key_exchange_response_type_0))

/**
 * Get the buffer containing the signature length in a type 0 key exchange response
 *
 * @param req The cerberus_protocol_key_exchange_response_type_0 structure containing the message.
 */
#define	cerberus_protocol_key_exchange_type_0_response_sig_len(req)	\
	(*((uint16_t*) (cerberus_protocol_key_exchange_type_0_response_key_data (req) + req->key_len)))

/**
 * Get the buffer containing the signature data in a type 0 key exchange response
 *
 * @param req The cerberus_protocol_key_exchange_response_type_0 structure containing the message.
 */
#define	cerberus_protocol_key_exchange_type_0_response_sig_data(req)	\
	(cerberus_protocol_key_exchange_type_0_response_key_data (req) + req->key_len + \
		sizeof (uint16_t))

/**
 * Maximum signature length that can be returned in a single request
 *
 * @param req The command request structure containing the message.
 */
#define	CERBERUS_PROTOCOL_KEY_EXCHANGE_TYPE_0_RESPONSE_MAX_SIG_DATA(req)	\
	(CERBERUS_PROTOCOL_KEY_EXCHANGE_TYPE_0_RESPONSE_MAX_KEY_DATA (req) - \
		((struct cerberus_protocol_key_exchange_response_type_0*) (req->data))->key_len - \
			sizeof (uint16_t))

/**
 * Get the buffer containing the HMAC length in a type 0 key exchange response
 *
 * @param req The cerberus_protocol_key_exchange_response_type_0 structure containing the message.
 */
#define	cerberus_protocol_key_exchange_type_0_response_hmac_len(req)	\
	(*((uint16_t*) (((uint8_t*) cerberus_protocol_key_exchange_type_0_response_sig_data (req)) + \
		cerberus_protocol_key_exchange_type_0_response_sig_len (req))))

/**
 * Get the buffer containing the HMAC data in a type 0 key exchange response
 *
 * @param req The cerberus_protocol_key_exchange_response_type_0 structure containing the message.
 */
#define	cerberus_protocol_key_exchange_type_0_response_hmac_data(req)	\
	(((uint8_t*)(cerberus_protocol_key_exchange_type_0_response_sig_data (req))) + \
		sizeof (uint16_t) + cerberus_protocol_key_exchange_type_0_response_sig_len (req))

/**
 * Maximum signature length that can be returned in a single request
 *
 * @param req The command request structure containing the message.
 */
#define	CERBERUS_PROTOCOL_KEY_EXCHANGE_TYPE_0_RESPONSE_MAX_HMAC_DATA(req)	\
	(CERBERUS_PROTOCOL_KEY_EXCHANGE_TYPE_0_RESPONSE_MAX_SIG_DATA (req) - sizeof (uint16_t) - \
		cerberus_protocol_key_exchange_type_0_response_sig_len ( \
			((struct cerberus_protocol_key_exchange_response_type_0*)req->data)))

/**
 * Get the total message length for a type 0 key exchange response.
 *
 * @param key_len Length of the key data.
 */
#define	cerberus_protocol_key_exchange_type_0_response_length(key_len, sig_len, hmac_len)	\
	(key_len + sig_len + hmac_len + \
	sizeof (struct cerberus_protocol_key_exchange_response_type_0) + sizeof (uint16_t) * 2)

/**
 * Cerberus protocol key exchange type 1 request format
 */
struct cerberus_protocol_key_exchange_type_1 {
	struct cerberus_protocol_key_exchange common;			/**< Common request fields between all key exchange requests */
	uint16_t pairing_key_len;								/**< Length in bytes of the pairing key */
};

/**
 * Get the buffer containing the HMAC in a type 1 key exchange request
 *
 * @param req The command request structure containing the message.
 */
#define	cerberus_protocol_key_exchange_type_1_hmac_data(req)	\
	(((uint8_t*) req) + sizeof (struct cerberus_protocol_key_exchange_type_1))

/**
 * Get the total message length for a type 1 key exchange request.
 *
 * @param len Length of the HMAC data.
 */
#define	cerberus_protocol_key_exchange_type_1_length(len)	\
	(len + sizeof (struct cerberus_protocol_key_exchange_type_1))

/**
 * Get the HMAC length from a type 1 key exchange request.
 *
 * @param req The command request structure containing the message.
 */
#define	cerberus_protocol_key_exchange_type_1_hmac_len(req)	\
	(req->length - sizeof (struct cerberus_protocol_key_exchange_type_1))

/**
 * Cerberus protocol key exchange type 2 request format
 */
struct cerberus_protocol_key_exchange_type_2 {
	struct cerberus_protocol_key_exchange common;			/**< Common request fields between all key exchange requests */
};

/**
 * Get the buffer containing the HMAC in a type 2 key exchange request
 *
 * @param req The command request structure containing the message.
 */
#define	cerberus_protocol_key_exchange_type_2_hmac_data(req)	\
	(((uint8_t*) req) + sizeof (struct cerberus_protocol_key_exchange_type_2))

/**
 * Get the total message length for a type 2 key exchange request.
 *
 * @param len Length of the HMAC data.
 */
#define	cerberus_protocol_key_exchange_type_2_length(len)	\
	(len + sizeof (struct cerberus_protocol_key_exchange_type_2))

/**
 * Get the HMAC length from a type 2 key exchange request.
 *
 * @param req The command request structure containing the message.
 */
#define	cerberus_protocol_key_exchange_type_2_hmac_len(req)	\
	(req->length - sizeof (struct cerberus_protocol_key_exchange_type_2))

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
 * Cerberus protocol get attestation data response format
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
			uint8_t processing:1;							/**< Additional processing on ECDH seed */
			uint8_t reserved:7;								/**< Unused. */
		} ecdh;
		uint8_t raw;										/**< Raw seed parameter value */
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

/**
 * Cerberus protocol session sync request format
 */
struct cerberus_protocol_session_sync {
	struct cerberus_protocol_header header;					/**< Message header */
	uint32_t rn_req;										/**< Random number */
};

/**
 * Cerberus protocol session sync response format
 */
struct cerberus_protocol_session_sync_response {
	struct cerberus_protocol_header header;					/**< Message header */
};

/**
 * Get pointer to the HMAC in a session sync response
 *
 * @param req The command request structure containing the message.
 */
#define	cerberus_protocol_session_sync_hmac_data(req)	\
	(((uint8_t*) req) + sizeof (struct cerberus_protocol_session_sync_response))

/**
 * Get the total message length for a session sync response.
 *
 * @param len Length of the HMAC data.
 */
#define	cerberus_protocol_session_sync_length(len)	\
	(len + sizeof (struct cerberus_protocol_session_sync_response))

/**
 * Maximum length that be used for the HMAC buffer in a session sync response.
 *
 * @param req The command request structure containing the message.
 */
#define	CERBERUS_PROTOCOL_MAX_SESSION_SYNC_HMAC_LEN(req)	\
	((req->max_response - sizeof (struct cerberus_protocol_session_sync_response)))
#pragma pack(pop)


int cerberus_protocol_fw_update_init (struct firmware_update_control *control,
	struct cmd_interface_msg *request);
int cerberus_protocol_fw_update (struct firmware_update_control *control,
	struct cmd_interface_msg *request);
int cerberus_protocol_fw_update_start (struct firmware_update_control *control,
	struct cmd_interface_msg *request);

int cerberus_protocol_get_log_info (struct pcr_store *pcr_store,
	struct cmd_interface_msg *request);
int cerberus_protocol_log_read (struct pcr_store *pcr_store, struct hash_engine *hash,
	struct cmd_interface_msg *request);
int cerberus_protocol_log_clear (struct cmd_background *background,
	struct cmd_interface_msg *request);

int cerberus_protocol_get_pfm_id (struct pfm_manager* pfm_mgr[], uint8_t num_ports,
	struct cmd_interface_msg *request);
int cerberus_protocol_get_pfm_fw (struct pfm_manager* pfm_mgr[], uint8_t num_ports,
	struct cmd_interface_msg *request);

struct manifest_cmd_interface* cerberus_protocol_get_pfm_cmd_interface (
	struct manifest_cmd_interface *pfm_0, struct manifest_cmd_interface *pfm_1, uint8_t port);

int cerberus_protocol_pfm_update_init (struct manifest_cmd_interface* pfm_cmd[], uint8_t num_ports,
	struct cmd_interface_msg *request);
int cerberus_protocol_pfm_update (struct manifest_cmd_interface *pfm_cmd[], uint8_t num_ports,
	struct cmd_interface_msg *request);
int cerberus_protocol_pfm_update_complete (struct manifest_cmd_interface *pfm_cmd[],
	uint8_t num_ports, struct cmd_interface_msg *request);

int cerberus_protocol_get_host_reset_status (struct host_control *host_0_ctrl,
	struct host_control *host_1_ctrl, struct cmd_interface_msg *request);

int cerberus_protocol_unseal_message (struct cmd_background *background,
	struct cmd_interface_msg *request);
int cerberus_protocol_unseal_message_result (struct cmd_background *background,
	struct cmd_interface_msg *request);

int cerberus_protocol_reset_config (struct cmd_authorization *cmd_auth,
	struct cmd_background *background, struct cmd_interface_msg *request);

struct recovery_image_cmd_interface* cerberus_protocol_get_recovery_image_cmd_interface (
	struct recovery_image_cmd_interface *recovery_0,
	struct recovery_image_cmd_interface *recovery_1, uint8_t port);
struct recovery_image_manager* cerberus_protocol_get_recovery_image_manager (
	struct recovery_image_manager *recovery_manager_0,
	struct recovery_image_manager *recovery_manager_1, uint8_t port);

int cerberus_protocol_prepare_recovery_image ( struct recovery_image_cmd_interface *recovery_0,
	struct recovery_image_cmd_interface *recovery_1, struct cmd_interface_msg *request);
int cerberus_protocol_update_recovery_image (struct recovery_image_cmd_interface *recovery_0,
	struct recovery_image_cmd_interface *recovery_1, struct cmd_interface_msg *request);
int cerberus_protocol_activate_recovery_image (struct recovery_image_cmd_interface *recovery_0,
	struct recovery_image_cmd_interface *recovery_1, struct cmd_interface_msg *request);
int cerberus_protocol_get_recovery_image_id (struct recovery_image_manager *manager_0,
	struct recovery_image_manager *manager_1, struct cmd_interface_msg *request);

int cerberus_protocol_get_attestation_data (struct pcr_store *store,
	struct cmd_interface_msg *request);

int cerberus_protocol_key_exchange (struct session_manager *session,
	struct cmd_interface_msg *request, uint8_t encrypted);
int cerberus_protocol_session_sync (struct session_manager *session,
	struct cmd_interface_msg *request, uint8_t encrypted);


#endif /* CERBERUS_PROTOCOL_OPTIONAL_COMMANDS_H_ */
