// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_PROTOCOL_H_
#define CERBERUS_PROTOCOL_H_

#include <stdint.h>
#include "mctp/mctp_protocol.h"


#define CERBERUS_PROTOCOL_MIN_MSG_LEN						(sizeof (struct cerberus_protocol_header))
#define CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG				(MCTP_PROTOCOL_MAX_PAYLOAD_PER_MSG - CERBERUS_PROTOCOL_MIN_MSG_LEN)

#define CERBERUS_PROTOCOL_CMD(name, type, req) 				type name = (type) &(req)->data[CERBERUS_PROTOCOL_MIN_MSG_LEN]
#define CERBERUS_PROTOCOL_CMD_LEN(type)						(CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (type))

#define CERBERUS_PROTOCOL_MSFT_PCI_VID						0x1414
#define CERBERUS_PROTOCOL_PROTOCOL_VERSION					2


/**
 * The maximum length of the version string that can be reported by the protocol.
 */
#define	CERBERUS_PROTOCOL_FW_VERSION_LEN					32


/**
 * Cerberus protocol commands
 */
enum {
	CERBERUS_PROTOCOL_GET_FW_VERSION = 0x01,				/**< Get FW version */
	CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES,				/**< Get device capabilities */
	CERBERUS_PROTOCOL_GET_DEVICE_ID,						/**< Get device ID */
	CERBERUS_PROTOCOL_GET_DEVICE_INFO,						/**< Get device information */
	CERBERUS_PROTOCOL_EXPORT_CSR = 0x20,					/**< Export CSR */
	CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT,				/**< Import CA signed certificate */
	CERBERUS_PROTOCOL_GET_SIGNED_CERT_STATE,				/**< Get state of the signed certificates */
	CERBERUS_PROTOCOL_GET_HOST_STATE = 0x40,				/**< Get Host reset state */
	CERBERUS_PROTOCOL_GET_LOG_INFO = 0x4F,					/**< Get log info */
	CERBERUS_PROTOCOL_READ_LOG,								/**< Read back log */
	CERBERUS_PROTOCOL_CLEAR_LOG,							/**< Clear log */
	CERBERUS_PROTOCOL_GET_PFM_ID = 0x59,					/**< Get PFM ID */
	CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW,					/**< Get PFM supported FW versions */
	CERBERUS_PROTOCOL_INIT_PFM_UPDATE,						/**< Initialize PFM update process */
	CERBERUS_PROTOCOL_UPDATE_PFM,							/**< Send PFM update data */
	CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE,					/**< Trigger Cerberus to verify PFM update */
	CERBERUS_PROTOCOL_GET_CFM_ID,							/**< Get CFM ID */
	CERBERUS_PROTOCOL_INIT_CFM_UPDATE,						/**< Initialize CFM update process */
	CERBERUS_PROTOCOL_UPDATE_CFM,							/**< Send CFM update data */
	CERBERUS_PROTOCOL_COMPLETE_CFM_UPDATE,					/**< Trigger Cerberus to verify CFM update */
	CERBERUS_PROTOCOL_GET_PCD_ID,							/**< Get PCD ID */
	CERBERUS_PROTOCOL_INIT_PCD_UPDATE,						/**< Initialize PCD update process */
	CERBERUS_PROTOCOL_UPDATE_PCD,							/**< Send PCD update data */
	CERBERUS_PROTOCOL_COMPLETE_PCD_UPDATE,					/**< Trigger Cerberus to verify PCD update */
	CERBERUS_PROTOCOL_INIT_FW_UPDATE,						/**< Intiailize FW update process */
	CERBERUS_PROTOCOL_UPDATE_FW,							/**< Send FW update data */
	CERBERUS_PROTOCOL_GET_UPDATE_STATUS,					/**< Get update status */
	CERBERUS_PROTOCOL_COMPLETE_FW_UPDATE,					/**< Trigger Cerberus to start FW update */
	CERBERUS_PROTOCOL_RESET_CONFIG,							/**< Erase configuration from the device. */
	CERBERUS_PROTOCOL_GET_CONFIG_ID = 0x70,					/**< Get configuration IDs */
	CERBERUS_PROTOCOL_TRIGGER_FW_RECOVERY,					/**< Trigger Cerberus FW recovery */
	CERBERUS_PROTOCOL_PREPARE_RECOVERY_IMAGE,				/**< Prepare to receive host recovery data */
	CERBERUS_PROTOCOL_UPDATE_RECOVERY_IMAGE,				/**< Send host recovery image data */
	CERBERUS_PROTOCOL_ACTIVATE_RECOVERY_IMAGE,				/**< Activate host recovery image */
	CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION,			/**< Get active host recovery image version ID */
	CERBERUS_PROTOCOL_ERROR = 0x7F,							/**< Error response message */
	CERBERUS_PROTOCOL_GET_PCR,								/**< Get PCR */
	CERBERUS_PROTOCOL_GET_DIGEST,							/**< Get certificate digest */
	CERBERUS_PROTOCOL_GET_CERTIFICATE,						/**< Get certificate */
	CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE,				/**< Attestation challenge */
	CERBERUS_PROTOCOL_EXHANGE_KEYS,							/**< Exchange pre-master session keys */
	CERBERUS_PROTOCOL_EXTEND_PCR = 0x86,					/**< Set PCR */
	CERBERUS_PROTOCOL_RESET_COUNTER,						/**< Reset counter */
	CERBERUS_PROTOCOL_UNSEAL_MESSAGE = 0x89,				/**< Start unsealing message */
	CERBERUS_PROTOCOL_UNSEAL_MESSAGE_RESULT,				/**< Get unsealing result*/
	CERBERUS_PROTOCOL_DEBUG_START_ATTESTATION,				/**< Debug command to start attestation */
	CERBERUS_PROTOCOL_DEBUG_GET_ATTESTATION_STATE,			/**< Debug command to get attestation status */
	CERBERUS_PROTOCOL_GET_CFM_SUPPORTED_COMPONENT_IDS,		/**< Get CFM supported component IDs */
	CERBERUS_PROTOCOL_GET_EXT_UPDATE_STATUS,				/**< Get extended update status */
	CERBERUS_PROTOCOL_DEBUG_FILL_LOG,						/**< Debug command to fill up debug log */
	CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CERT,		/**< Debug command to retrieve device certificate */
	CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CERT_DIGEST,	/**< Debug command to retrieve device certificate digest */
	CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CHALLENGE,	/**< Debug command to retrieve device challenge */
};

/**
 * Cerberus error codes
 */
enum
{
	CERBERUS_PROTOCOL_NO_ERROR,								/**< Success */
	CERBERUS_PROTOCOL_ERROR_INVALID_REQ,					/**< Invalid request */
	CERBERUS_PROTOCOL_ERROR_BUSY = 03,						/**< Device busy */
	CERBERUS_PROTOCOL_ERROR_UNSPECIFIED,					/**< Unspecified error */
	CERBERUS_PROTOCOL_ERROR_INVALID_CHECKSUM = 0xF0,		/**< Invalid checksum */
	CERBERUS_PROTOCOL_ERROR_OUT_OF_ORDER_MSG,				/**< EOM before SOM */
	CERBERUS_PROTOCOL_ERROR_AUTHENTICATION,					/**< Authentication not established */
	CERBERUS_PROTOCOL_ERROR_OUT_OF_SEQ_WINDOW,				/**< Message received out of sequence window */
	CERBERUS_PROTOCOL_ERROR_INVALID_PACKET_LEN,				/**< Invalid message size */
	CERBERUS_PROTOCOL_ERROR_MSG_OVERFLOW					/**< MCTP message too large */
};

/**
 * Identifier for the type of update status.
 */
enum {
	CERBERUS_PROTOCOL_FW_UPDATE = 0,						/**< Cerberus FW update. */
	CERBERUS_PROTOCOL_PFM_UPDATE,							/**< PFM update. */
	CERBERUS_PROTOCOL_CFM_UPDATE,							/**< CFM update. */
	CERBERUS_PROTOCOL_PCD_UPDATE,							/**< PCD update. */
	CERBERUS_PROTOCOL_HOST_FW_NEXT_RESET,					/**< Host FW reset verification. */
	CERBERUS_PROTOCOL_RECOVERY_IMAGE_UPDATE,				/**< Recovery image update. */
	CERBERUS_PROTOCOL_CONFIG_RESET_UPDATE,					/**< Configuration reset. */
	NUM_CERBERUS_PROTOCOL_UPDATE_TYPES						/**< Number of update types. */
};


#pragma pack(push, 1)
/**
 * Cerberus portion of packet header
 */
struct cerberus_protocol_header
{
	uint8_t msg_type:7;										/**< MCTP message type */
	uint8_t integrity_check:1;								/**< MCTP message integrity check */
	uint16_t pci_vendor_id;									/**< PCI vendor ID */
	uint8_t seq_num:5;										/**< Sequence Number */
	uint8_t crypt:1;										/**< Message Encryption Bit */
	uint8_t d_bit:1;										/**< D-bit */
	uint8_t rq:1;											/**< Request bit */
	uint8_t command;										/**< Command ID */
};
#pragma pack(pop)


#endif /* CERBERUS_PROTOCOL_H_ */
