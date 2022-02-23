// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_PROTOCOL_REQUIRED_COMMANDS_H_
#define CERBERUS_PROTOCOL_REQUIRED_COMMANDS_H_

#include <stdint.h>
#include "cmd_interface/cerberus_protocol.h"
#include "cmd_interface/cmd_interface.h"
#include "cmd_interface/cmd_background.h"
#include "cmd_interface/device_manager.h"
#include "cmd_interface/cmd_device.h"
#include "cmd_interface/session_manager.h"
#include "attestation/attestation_slave.h"
#include "riot/riot_key_manager.h"


/**
 * Valid reset counter types.
 */
enum {
	CERBERUS_PROTOCOL_CERBERUS_RESET = 0,					/**< Cerberus reset counter type */
	CERBERUS_PROTOCOL_COMPONENT_RESET						/**< Component reset counter type */
};

#pragma pack(push, 1)
/**
 * Cerberus protocol device capabilities request format
 */
struct cerberus_protocol_device_capabilities {
	struct cerberus_protocol_header header;					/**< Message header */
	struct device_manager_capabilities capabilities;		/**< Device capabilities request data. */
};

/**
 * Cerberus protocol device capabilities response format
 */
struct cerberus_protocol_device_capabilities_response {
	struct cerberus_protocol_header header;					/**< Message header */
	struct device_manager_full_capabilities capabilities;	/**< Device capabilities response data. */
};

/**
 * Cerberus protocol get certificate digest request format
 */
struct cerberus_protocol_get_certificate_digest {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t slot_num;										/**< Slot number of target chain */
	uint8_t key_alg;										/**< Key exchange algorithm */
};

/**
 * Cerberus protocol get certificate digest response format
 */
struct cerberus_protocol_get_certificate_digest_response {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t capabilities;									/**< Capabilities field */
	uint8_t num_digests;									/**< Number of digests returned */
};

/**
 * Get the buffer containing the certificate digests
 */
#define	cerberus_protocol_certificate_digests(resp)	(((uint8_t*) resp) + sizeof (*resp))

/**
 * Get the total message length for a get certificate digests response message.
 *
 * @param len Length of the digest data.
 */
#define	cerberus_protocol_get_certificate_digest_response_length(len)	\
	(len + sizeof (struct cerberus_protocol_get_certificate_digest_response))

/**
 * Maximum amount of digest data that can be returned in a single request
 *
 * @param req The command request structure containing the message.
 */
#define	CERBERUS_PROTOCOL_MAX_CERT_DIGESTS(req)	\
	(req->max_response - sizeof (struct cerberus_protocol_get_certificate_digest_response))

/**
 * Cerberus protocol get certificate request format
 */
struct cerberus_protocol_get_certificate {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t slot_num;										/**< Slot number of target chain */
	uint8_t cert_num;										/**< Certificate number in chain */
	uint16_t offset;										/**< Offset in bytes from start of certificate */
	uint16_t length;										/**< Number of bytes to read back, 0 for max payload length */
};

/**
 * Cerberus protocol get certificate response format
 */
struct cerberus_protocol_get_certificate_response {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t slot_num;										/**< Slot number of target chain */
	uint8_t cert_num;										/**< Certificate number in chain */
};

/**
 * Get the buffer containing the certificate
 */
#define	cerberus_protocol_certificate(resp)	(((uint8_t*) resp) + sizeof (*resp))

/**
 * Get the total message length for a get certificate response message.
 *
 * @param len Length of the certificate data.
 */
#define	cerberus_protocol_get_certificate_response_length(len)	\
	(len + sizeof (struct cerberus_protocol_get_certificate_response))

/**
 * Maximum amount of certificate data that can be returned in a single request
 *
 * @param req The command request structure containing the message.
 */
#define	CERBERUS_PROTOCOL_MAX_CERT_DATA(req)	\
	(req->max_response - sizeof (struct cerberus_protocol_get_certificate_response))

/**
 * Cerberus protocol challenge request format
 */
struct cerberus_protocol_challenge {
	struct cerberus_protocol_header header;					/**< Message header */
	struct attestation_challenge challenge;					/**< Requestor challenge seed */
};

/**
 * Cerberus protocol challenge response format
 */
struct cerberus_protocol_challenge_response {
	struct cerberus_protocol_header header;					/**< Message header */
	struct attestation_response challenge;					/**< Attestation information */
	uint8_t digest;											/**< First byte of the variable length digest. */
};

/**
 * Get the buffer containing the challenge response signature.
 *
 * @param resp Pointer to a challenge response message.
 */
#define	cerberus_protocol_challenge_get_signature(resp)	\
	((&((resp)->digest)) + (resp)->challenge.digests_size)

/**
 * Get the total message length for a challenge response message.
 *
 * @param resp Pointer to a challenge response message.
 */
#define	cerberus_protocol_challenge_response_length(resp)	\
	(sizeof (struct cerberus_protocol_challenge_response) - 1 + (resp)->challenge.digests_size)

/**
 * Cerberus protocol import signed certificate request format
 */
struct cerberus_protocol_import_certificate {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t index;											/**< Index of the certificate being imported. */
	uint16_t cert_length;									/**< Length of the certificate data. */
	uint8_t certificate;									/**< First byte of the variable length data. */
};

/**
 * Cerberus protocol export CSR request format
 */
struct cerberus_protocol_export_csr {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t index;											/**< Index of the CSR to export */
};

/**
 * Cerberus protocol export CSR response format
 */
struct cerberus_protocol_export_csr_response {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t csr;											/**< First byte of the variable length data. */
};

/**
 * Get the total message length for an export CSR response message.
 *
 * @param len Length of the CSR data.
 */
#define	cerberus_protocol_export_csr_response_length(len)	\
	((len + sizeof (struct cerberus_protocol_export_csr_response)) - sizeof (uint8_t))

/**
 * Maximum amount of CSR data that can be returned in the request
 *
 * @param req The command request structure containing the message.
 */
#define	CERBERUS_PROTOCOL_MAX_CSR_DATA(req)	\
	((req->max_response - sizeof (struct cerberus_protocol_export_csr_response)) + sizeof (uint8_t))

/**
 * Maximum amount of CSR data supported by the local device's configuration
 */
#define	CERBERUS_PROTOCOL_LOCAL_MAX_CSR_DATA	\
	((MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - sizeof (struct cerberus_protocol_export_csr_response)) + \
	sizeof (uint8_t))

/**
 * Cerberus protocol get certificate state request format
 */
struct cerberus_protocol_get_certificate_state {
	struct cerberus_protocol_header header;					/**< Message header */
};

/**
 * Cerberus protocol get certificate state response format
 */
struct cerberus_protocol_get_certificate_state_response {
	struct cerberus_protocol_header header;					/**< Message header */
	uint32_t cert_state;									/**< Current state of signed certificate validation. */
};

/**
 * Cerberus protocol get device information request format
 */
struct cerberus_protocol_get_device_info {
	struct cerberus_protocol_header header;					/**< Message header */
    uint8_t info_index;										/**< The device information index. */
};

/**
 * Cerberus protocol get device information request format
 */
struct cerberus_protocol_get_device_info_response {
	struct cerberus_protocol_header header;					/**< Message header */
    uint8_t info;											/**< First byte of the variable length data. */
};

/**
 * Get the total message length for a get device information response message.
 *
 * @param len Length of the device info data.
 */
#define	cerberus_protocol_get_device_info_response_length(len)	\
	((len + sizeof (struct cerberus_protocol_get_device_info_response)) - sizeof (uint8_t))

/**
 * Maximum amount of device info data that can be returned in the request
 *
 * @param req The command request structure containing the message.
 */
#define	CERBERUS_PROTOCOL_MAX_DEV_INFO_DATA(req)	\
	((req->max_response - sizeof (struct cerberus_protocol_get_device_info_response)) + sizeof (uint8_t))

/**
 * Cerberus protocol get FW version request format
 */
struct cerberus_protocol_get_fw_version {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t area;											/**< The target firmware area index. */
};

/**
 * Cerberus protocol get FW version response format
 */
struct cerberus_protocol_get_fw_version_response {
	struct cerberus_protocol_header header;					/**< Message header */
	char version[CERBERUS_PROTOCOL_FW_VERSION_LEN];			/**< Version ID */
};

/**
 * Cerberus protocol get device ID request format
 */
struct cerberus_protocol_get_device_id {
	struct cerberus_protocol_header header;					/**< Message header */
};

/**
 * Cerberus protocol get device ID response format
 */
struct cerberus_protocol_get_device_id_response {
	struct cerberus_protocol_header header;					/**< Message header */
	uint16_t vendor_id;										/**< Vendor ID */
	uint16_t device_id;										/**< Device ID */
	uint16_t subsystem_vid;									/**< Subsystem vendor ID */
	uint16_t subsystem_id;									/**< Subsystem ID */
};

/**
 * Cerberus protocol reset counter request format
 */
struct cerberus_protocol_reset_counter {
	struct cerberus_protocol_header header;					/**< Message header */
	uint8_t type;											/**< Count type to retrieve */
	uint8_t port;											/**< Port identifier */
};

/**
 * Cerberus protocol reset counter response format
 */
struct cerberus_protocol_reset_counter_response {
	struct cerberus_protocol_header header;					/**< Message header */
	uint16_t counter;										/**< Current counter value */
};
#pragma pack(pop)


int cerberus_protocol_get_fw_version (struct cmd_interface_fw_version *fw_version,
	struct cmd_interface_msg *request);

int cerberus_protocol_get_certificate_digest (struct attestation_slave *attestation,
	struct session_manager *session, struct cmd_interface_msg *request);
int cerberus_protocol_get_certificate (struct attestation_slave *attestation,
	struct cmd_interface_msg *request);
int cerberus_protocol_get_challenge_response (struct attestation_slave *attestation,
	struct session_manager *session, struct cmd_interface_msg *request);

int cerberus_protocol_export_csr (struct riot_key_manager *riot,
	struct cmd_interface_msg *request);
int cerberus_protocol_import_ca_signed_cert (struct riot_key_manager *riot,
	struct cmd_background *background, struct cmd_interface_msg *request);
int cerberus_protocol_get_signed_cert_state (struct cmd_background *background,
	struct cmd_interface_msg *request);

int cerberus_protocol_get_device_capabilities (struct device_manager *device_mgr,
	struct cmd_interface_msg *request);

int cerberus_protocol_get_device_info (struct cmd_device *device,
	struct cmd_interface_msg *request);
int cerberus_protocol_get_device_id (struct cmd_interface_device_id *id,
	struct cmd_interface_msg *request);

int cerberus_protocol_reset_counter (struct cmd_device *device,
	struct cmd_interface_msg *request);

int cerberus_protocol_process_error_response (struct cmd_interface_msg *response);

#endif /* CERBERUS_PROTOCOL_REQUIRED_COMMANDS_H_ */
