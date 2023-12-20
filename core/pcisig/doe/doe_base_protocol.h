// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef DOE_BASE_PROTOCOL_H_
#define DOE_BASE_PROTOCOL_H_

#include <stdint.h>
#include "platform_config.h"


/**
 * Maximum specification supported size of a DOE message.
 */
#define DOE_MESSAGE_SPEC_MAX_SIZE_IN_BYTES			0x00100000
#define DOE_MESSAGE_SPEC_MAX_SIZE_IN_DWORDS			0x00040000

/* Configurable DOE protocol parameters. Defaults can be overridden in platform_config.h. */

#ifdef DOE_MESSAGE_PLATFORM_MAX_SIZE_IN_BYTES
#define DOE_MESSAGE_MAX_SIZE_IN_BYTES		DOE_MESSAGE_PLATFORM_MAX_SIZE_IN_BYTES
#else
#define DOE_MESSAGE_MAX_SIZE_IN_BYTES		DOE_MESSAGE_SPEC_MAX_SIZE_IN_BYTES
#endif

#if DOE_MESSAGE_MAX_SIZE_IN_BYTES > DOE_MESSAGE_SPEC_MAX_SIZE_IN_BYTES
#error "Invalid DOE maximum message length."
#endif

/**
 * Length of the DOE data object + header, in number of dwords.
 * A value of 00000h indicates 2^18 dwords == 2^20 bytes.
 */
#define DOE_MESSAGE_MAX_SIZE_INDICATOR				0

#pragma pack(push, 1)

/**
 * Defines the interface for a DOE communication channel to send and receive DOE messages.
 */
struct doe_base_protocol_transport_header {
	uint16_t vendor_id;			/**< Vendor identification */
	uint8_t data_object_type;	/**< DOE payload type */
	uint8_t reserved;			/**< Unused */
	/**
	 * Length of the data object + this header, in number of dwords.
	 * Only bit[0~17] are valid, bit[18~31] are reserved.
	 * A value of 00000h indicates 2^18 dwords == 2^20 bytes.
	 */
	uint32_t length;
};

#pragma pack(pop)

/**
 * Minimum DOE message size. Header (8 bytes) + Min payload (4 bytes).
 */
#define DOE_MESSAGE_MIN_SIZE_IN_BYTES 		12
#define DOE_MESSAGE_MIN_SIZE_IN_DWORDS		(DOE_MESSAGE_MIN_SIZE_IN_BYTES / 4)

#if DOE_MESSAGE_MAX_SIZE_IN_BYTES < DOE_MESSAGE_MIN_SIZE_IN_BYTES
#error "DOE configured maximum message length is less than minimum."
#endif

/**
 * Byte aligment of a DOE message.
 */
#define DOE_ALIGNMENT						4

/**
 * PCISIG Vendor Id of a DOE message.
 */
#define DOE_VENDOR_ID_PCISIG				0x0001

/**
 * Supported Ids of DOE message payloads.
 */
#define DOE_DATA_OBJECT_TYPE_SPDM			0x01
#define DOE_DATA_OBJECT_TYPE_SECURED_SPDM	0x02

/**
 * Gets the object type of the payload from the DOE header.
 */
#define DOE_DATA_OBJECT_TYPE(msg) \
	(((struct doe_base_protocol_transport_header*) msg)->data_object_type)


#endif /* DOE_BASE_PROTOCOL_H_ */