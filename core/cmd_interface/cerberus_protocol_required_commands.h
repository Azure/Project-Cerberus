// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_PROTOCOL_REQUIRED_COMMANDS_H_
#define CERBERUS_PROTOCOL_REQUIRED_COMMANDS_H_

#include <stdint.h>
#include "attestation/attestation_slave.h"
#include "cmd_interface.h"
#include "cmd_background.h"
#include "device_manager.h"
#include "cmd_device.h"


/**
 * Valid reset counter types.
 */
enum {
	CERBERUS_PROTOCOL_CERBERUS_RESET = 0,					/**< Cerberus reset counter type */
	CERBERUS_PROTOCOL_COMPONENT_RESET						/**< Component reset counter type */
};

#pragma pack(push, 1)
/**
 * Device capabilities packet format
 */
struct cerberus_protocol_device_capabilities {
	struct device_manager_capabilities capabilities;		/**< Device capabilities */
};

/**
 * Device capabilities response packet format
 */
struct cerberus_protocol_device_capabilities_response {
	struct device_manager_capabilities capabilities;		/**< Device capabilities */
	uint8_t max_timeout;									/**< Maximum timeout in 10ms multiples */
	uint8_t max_sig;										/**< Maximum signature response delay in 10ms multiples */
};

/**
 * Cerberus protocol get certificate digest request packet format
 */
struct cerberus_protocol_get_certificate_digest_request_packet {
	uint8_t reserved;										/**< Reserved */
	uint8_t key_alg;										/**< Key exchange algorithm */
};

/**
 * Cerberus protocol get certificate digest response header format
 */
struct cerberus_protocol_get_certificate_digest_response_header {
	uint8_t capabilities;									/**< Capabilities field */
	uint8_t num_digests;									/**< Number of digests returned */
};

/**
 * Cerberus protocol get certificate request packet format
 */
struct cerberus_protocol_get_certificate_request_packet {
	uint8_t slot_num;										/**< Slot number of target chain */
	uint8_t cert_num;										/**< Certificate number in chain */
	uint16_t offset;										/**< Offset in bytes from start of certificate */
	uint16_t length;										/**< Number of bytes to read back, 0 for max payload length */
};

/**
 * Cerberus protocol get certificate response header format
 */
struct cerberus_protocol_get_certificate_response_header {
	uint8_t slot_num;										/**< Slot number of target chain */
	uint8_t cert_num;										/**< Certificate number in chain */
};

/**
 * Cerberus protocol import signed certificate header format
 */
struct cerberus_protocol_import_certificate_request_packet {
	uint8_t index;											/**< Index of the certificate being imported. */
	uint16_t cert_length;									/**< Length of the certificate data. */
	uint8_t certificate;									/**< First byte of the variable length data. */
};

/**
 * Cerberus protocol export CSR request packet format
 */
struct cerberus_protocol_export_csr_request_packet {
	uint8_t index;											/**< Index */
};

/**
 * Cerberus protocol get signed certificate state response packet format
 */
struct cerberus_protocol_get_certificate_state_response_packet {
	uint32_t cert_state;									/**< Current state of signed certificate validation. */
};

/**
 * Cerberus protocol get device information request packet format
 */
struct cerberus_protocol_get_device_info_request_packet {
    uint8_t info;                                       	/**< The device information index. */
};

/**
 * Cerberus protocol get FW version request packet format
 */
struct cerberus_protocol_get_fw_version_request_packet {
	uint8_t area;											/**< The target firmware area index. */
};

/**
 * Cerberus protocol get FW version response packet format
 */
struct cerberus_protocol_get_fw_version_response_packet {
	char version[CERBERUS_PROTOCOL_FW_VERSION_LEN];			/**< Version ID */
};

/**
 * Cerberus protocol get device ID response packet format
 */
struct cerberus_protocol_get_device_id_response_packet {
	uint16_t vendor_id;										/**< Vendor ID */
	uint16_t device_id;										/**< Device ID */
	uint16_t subsystem_vid;									/**< Subsystem vendor ID */
	uint16_t subsystem_id;									/**< Subsystem ID */
};

/**
 * Cerberus protocol reset counter request packet format
 */
struct cerberus_protocol_reset_counter_request_packet {
	uint8_t type;
	uint8_t port;
};

/**
 * Cerberus protocol reset counter response packet format
 */
struct cerberus_protocol_reset_counter_response_packet {
	uint16_t counter;
};
#pragma pack(pop)


int cerberus_protocol_get_fw_version (struct cmd_interface_fw_version *fw_version,
	struct cmd_interface_request *request);

int cerberus_protocol_get_certificate_digest (struct attestation_slave *attestation,
	struct cmd_interface_request *request);
int cerberus_protocol_get_certificate (struct attestation_slave *attestation,
	struct cmd_interface_request *request);
int cerberus_protocol_get_challenge_response (struct attestation_slave *attestation,
	struct cmd_interface_request *request);

int cerberus_protocol_export_csr (struct riot_key_manager *riot,
	struct cmd_interface_request *request);
int cerberus_protocol_import_ca_signed_cert (struct riot_key_manager *riot,
	struct cmd_background *background, struct cmd_interface_request *request);
int cerberus_protocol_get_signed_cert_state (struct cmd_background *background,
	struct cmd_interface_request *request);

int cerberus_protocol_issue_get_device_capabilities (struct device_manager *device_mgr,
	uint8_t *buf, int buf_len);
int cerberus_protocol_get_device_capabilities (struct device_manager *device_mgr,
	struct cmd_interface_request *request, uint8_t device_num);

int cerberus_protocol_get_device_info (struct cmd_device *device,
	struct cmd_interface_request *request);
int cerberus_protocol_get_device_id (struct cmd_interface_device_id *id, 
	struct cmd_interface_request *request);

int cerberus_protocol_reset_counter (struct cmd_device *device,
	struct cmd_interface_request *request);


#endif // CERBERUS_PROTOCOL_REQUIRED_COMMANDS_H_
