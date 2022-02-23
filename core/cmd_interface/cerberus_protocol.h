// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_PROTOCOL_H_
#define CERBERUS_PROTOCOL_H_

#include <stdint.h>
#include "mctp/mctp_base_protocol.h"


#define CERBERUS_PROTOCOL_MIN_MSG_LEN						(sizeof (struct cerberus_protocol_header))
#define CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG				(MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - CERBERUS_PROTOCOL_MIN_MSG_LEN)

#define CERBERUS_PROTOCOL_MSFT_PCI_VID						0x1414
#define CERBERUS_PROTOCOL_PROTOCOL_VERSION					4

/**
 * AES IV and GCM tag lengths defined by protocol.
 */
#define CERBERUS_PROTOCOL_AES_GCM_TAG_LEN					16
#define CERBERUS_PROTOCOL_AES_IV_LEN						12

/**
 * The maximum length of the version string that can be reported by the protocol.
 */
#define	CERBERUS_PROTOCOL_FW_VERSION_LEN					32


/**
 * Cerberus protocol commands
 */
enum {
	CERBERUS_PROTOCOL_GET_FW_VERSION = 0x01,					/**< Get FW version */
	CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES,					/**< Get device capabilities */
	CERBERUS_PROTOCOL_GET_DEVICE_ID,							/**< Get device ID */
	CERBERUS_PROTOCOL_GET_DEVICE_INFO,							/**< Get device information */
	CERBERUS_PROTOCOL_EXPORT_CSR = 0x20,						/**< Export CSR */
	CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT,					/**< Import CA signed certificate */
	CERBERUS_PROTOCOL_GET_SIGNED_CERT_STATE,					/**< Get state of the signed certificates */
	CERBERUS_PROTOCOL_GET_HOST_STATE = 0x40,					/**< Get Host reset state */
	CERBERUS_PROTOCOL_GET_LOG_INFO = 0x4F,						/**< Get log info */
	CERBERUS_PROTOCOL_READ_LOG,									/**< Read back log */
	CERBERUS_PROTOCOL_CLEAR_LOG,								/**< Clear log */
	CERBERUS_PROTOCOL_GET_ATTESTATION_DATA,						/**< Retrieve raw data for log measurements */
	CERBERUS_PROTOCOL_GET_PFM_ID = 0x59,						/**< Get PFM ID */
	CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW,						/**< Get PFM supported FW versions */
	CERBERUS_PROTOCOL_INIT_PFM_UPDATE,							/**< Initialize PFM update process */
	CERBERUS_PROTOCOL_PFM_UPDATE,								/**< Send PFM update data */
	CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE,						/**< Trigger Cerberus to verify PFM update */
	CERBERUS_PROTOCOL_GET_CFM_ID,								/**< Get CFM ID */
	CERBERUS_PROTOCOL_INIT_CFM_UPDATE,							/**< Initialize CFM update process */
	CERBERUS_PROTOCOL_CFM_UPDATE,								/**< Send CFM update data */
	CERBERUS_PROTOCOL_COMPLETE_CFM_UPDATE,						/**< Trigger Cerberus to verify CFM update */
	CERBERUS_PROTOCOL_GET_PCD_ID,								/**< Get PCD ID */
	CERBERUS_PROTOCOL_INIT_PCD_UPDATE,							/**< Initialize PCD update process */
	CERBERUS_PROTOCOL_PCD_UPDATE,								/**< Send PCD update data */
	CERBERUS_PROTOCOL_COMPLETE_PCD_UPDATE,						/**< Trigger Cerberus to verify PCD update */
	CERBERUS_PROTOCOL_INIT_FW_UPDATE,							/**< Initialize FW update process */
	CERBERUS_PROTOCOL_FW_UPDATE,								/**< Send FW update data */
	CERBERUS_PROTOCOL_GET_UPDATE_STATUS,						/**< Get update status */
	CERBERUS_PROTOCOL_COMPLETE_FW_UPDATE,						/**< Trigger Cerberus to start FW update */
	CERBERUS_PROTOCOL_RESET_CONFIG,								/**< Erase configuration from the device. */
	CERBERUS_PROTOCOL_GET_CONFIG_ID = 0x70,						/**< Get configuration IDs */
	CERBERUS_PROTOCOL_TRIGGER_FW_RECOVERY,						/**< Trigger Cerberus FW recovery */
	CERBERUS_PROTOCOL_PREPARE_RECOVERY_IMAGE,					/**< Prepare to receive host recovery data */
	CERBERUS_PROTOCOL_UPDATE_RECOVERY_IMAGE,					/**< Send host recovery image data */
	CERBERUS_PROTOCOL_ACTIVATE_RECOVERY_IMAGE,					/**< Activate host recovery image */
	CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION,				/**< Get active host recovery image version ID */
	CERBERUS_PROTOCOL_ERROR = 0x7F,								/**< Error response message */
	CERBERUS_PROTOCOL_GET_PMR,									/**< Get a Platform Measurement Register */
	CERBERUS_PROTOCOL_GET_DIGEST,								/**< Get certificate digest */
	CERBERUS_PROTOCOL_GET_CERTIFICATE,							/**< Get certificate */
	CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE,					/**< Attestation challenge */
	CERBERUS_PROTOCOL_EXCHANGE_KEYS,							/**< Exchange pre-master session keys */
	CERBERUS_PROTOCOL_SESSION_SYNC,								/**< Session sync */
	CERBERUS_PROTOCOL_UPDATE_PMR = 0x86,						/**< Extend a Platform Measurement Register */
	CERBERUS_PROTOCOL_RESET_COUNTER,							/**< Reset counter */
	CERBERUS_PROTOCOL_UNSEAL_MESSAGE = 0x89,					/**< Start unsealing message */
	CERBERUS_PROTOCOL_UNSEAL_MESSAGE_RESULT,					/**< Get unsealing result*/
	CERBERUS_PROTOCOL_GET_CFM_SUPPORTED_COMPONENT_IDS = 0x8D,	/**< Get CFM supported component IDs */
	CERBERUS_PROTOCOL_GET_EXT_UPDATE_STATUS,					/**< Get extended update status */

	/* Special diagnostic commands to query for device health or other debug information. */
	CERBERUS_PROTOCOL_DIAG_HEAP_USAGE = 0xD0,					/**< Diagnostic command to get heap usage */

	/* Utilize the reserved command space for debugging.  Must be disabled in production. */
	CERBERUS_PROTOCOL_DEBUG_START_ATTESTATION = 0xF0,			/**< Debug command to start attestation */
	CERBERUS_PROTOCOL_DEBUG_GET_ATTESTATION_STATE,				/**< Debug command to get attestation status */
	CERBERUS_PROTOCOL_DEBUG_FILL_LOG,							/**< Debug command to fill up debug log */
	CERBERUS_PROTOCOL_DEBUG_RESERVED = 0xFF,					/**< Not available to use as a debug command. */
};

/**
 * Cerberus error codes
 */
enum {
	CERBERUS_PROTOCOL_NO_ERROR = 0x00,						/**< Success */
	CERBERUS_PROTOCOL_ERROR_INVALID_REQ,					/**< Invalid request */
	CERBERUS_PROTOCOL_ERROR_BUSY = 0x03,					/**< Device busy */
	CERBERUS_PROTOCOL_ERROR_UNSPECIFIED,					/**< Unspecified error */
	CERBERUS_PROTOCOL_ERROR_INVALID_CHECKSUM = 0xF0,		/**< Invalid checksum */
	CERBERUS_PROTOCOL_ERROR_OUT_OF_ORDER_MSG,				/**< EOM before SOM */
	CERBERUS_PROTOCOL_ERROR_AUTHENTICATION,					/**< Authentication not established */
	CERBERUS_PROTOCOL_ERROR_OUT_OF_SEQ_WINDOW,				/**< Message received out of sequence window */
	CERBERUS_PROTOCOL_ERROR_INVALID_PACKET_LEN,				/**< Invalid message size */
	CERBERUS_PROTOCOL_ERROR_MSG_OVERFLOW					/**< MCTP message too large */
};


#pragma pack(push, 1)
/**
 * Cerberus portion of packet header
 */
struct cerberus_protocol_header {
	uint8_t msg_type:7;										/**< MCTP message type */
	uint8_t integrity_check:1;								/**< MCTP message integrity check */
	uint16_t pci_vendor_id;									/**< PCI vendor ID */
	uint8_t reserved1:5;									/**< Reserved */
	uint8_t crypt:1;										/**< Message Encryption Bit */
	uint8_t reserved2:1;									/**< Reserved */
	uint8_t rq:1;											/**< Request bit */
	uint8_t command;										/**< Command ID */
};

/**
 * Structure of a Cerberus error message.
 */
struct cerberus_protocol_error {
	struct cerberus_protocol_header header;					/**< The message header. */
	uint8_t error_code;										/**< Overall error code. */
	uint32_t error_data;									/**< Detailed error information. */
};
#pragma pack(pop)


#endif /* CERBERUS_PROTOCOL_H_ */
