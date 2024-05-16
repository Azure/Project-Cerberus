// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_DISCOVERY_H_
#define SPDM_DISCOVERY_H_

#include <stdint.h>


/**
 * Device ID block success completion code
 */
#define SPDM_DISCOVERY_DEVICE_ID_BLOCK_CC_SUCCESS		0x00

/**
 * Static block ID to use for reporting device ID information in SPDM v1.2.
 */
#define SPDM_DISCOVERY_DEVICE_ID_BLOCK_ID				0xef


/**
 * SPDM Device ID descriptors
 */
enum spdm_discovery_device_id_descriptors {
	SPDM_DISCOVERY_DEVICE_ID_PCI_VID = 0x0000,						/**< PCI Vendor ID */
	SPDM_DISCOVERY_DEVICE_ID_IANA_ENTERPRISE_ID = 0x0001,			/**< IANA Enterprise ID */
	SPDM_DISCOVERY_DEVICE_ID_UUID = 0x0002,							/**< UUID */
	SPDM_DISCOVERY_DEVICE_ID_PNP_VID = 0x0003,						/**< PnP Vendor ID */
	SPDM_DISCOVERY_DEVICE_ID_ACPI_VID = 0x0004,						/**< ACPI Vendor ID */
	SPDM_DISCOVERY_DEVICE_ID_IEEE_COMPANY_ID = 0x0005,				/**< IEEE Assigned Company ID */
	SPDM_DISCOVERY_DEVICE_ID_SCSI_VID = 0x0006,						/**< SCSI Vendor ID */
	SPDM_DISCOVERY_DEVICE_ID_PCI_DEVICE_ID = 0x0100,				/**< PCI Device ID */
	SPDM_DISCOVERY_DEVICE_ID_PCI_SUBSYSTEM_VID = 0x0101,			/**< PCI Subsystem Vendor ID */
	SPDM_DISCOVERY_DEVICE_ID_PCI_SUBSYSTEM_ID = 0x0102,				/**< PCI Subsystem ID */
	SPDM_DISCOVERY_DEVICE_ID_PCI_REVISION_ID = 0x0103,				/**< PCI Revision ID */
	SPDM_DISCOVERY_DEVICE_ID_PNP_PRODUCT_ID = 0x0104,				/**< PnP Product ID */
	SPDM_DISCOVERY_DEVICE_ID_ACPI_PRODUCT_ID = 0x0105,				/**< ACPI Product ID */
	SPDM_DISCOVERY_DEVICE_ID_ASCII_MODEL_NUM_LONG_STR = 0x0106,		/**< ASCII Model Number (Long String) */
	SPDM_DISCOVERY_DEVICE_ID_ASCII_MODEL_NUM_SHORT_STR = 0x0107,	/**< ASCII Model Number (Short String) */
	SPDM_DISCOVERY_DEVICE_ID_SCSI_PRODUCT_ID = 0x0108,				/**< SCSI Product ID */
	SPDM_DISCOVERY_DEVICE_ID_UBM_CONTROLLER_DEVICE_CODE = 0x0106,	/**< UBM Controller Device Code */
	SPDM_DISCOVERY_DEVICE_ID_VENDOR_DEFINED = 0xFFFF,				/**< Vendor Defined */
};


#pragma pack(push, 1)
/**
 * Format of a device ID measurement block.  This is a custom measurement block format based on the
 * PLDM QueryDeviceIdentifiers command used to address device ID discovery gap in SPDM 1.1 and 1.2.
 * Later versions of the SPDM specification is expected to address this gap, so this block should be
 * only used in earlier SPDM specification versions.
 */
struct spdm_discovery_device_id_block {
	uint8_t completion_code;	/**< Completion code */
	uint32_t device_id_len;		/**< Total length of descriptors field */
	uint8_t descriptor_count;	/**< Number of descriptors in descriptors field */
};

/**
 * Format of a device ID descriptor.
 */
struct spdm_discovery_device_id_descriptor {
	uint16_t descriptor_type;	/**< Type of descriptor */
	uint16_t descriptor_len;	/**< Length of descriptor */
};

/**
 * Format of a descriptor containing a PCI ID.
 */
struct spdm_discovery_pci_id_descriptor {
	uint16_t descriptor_type;	/**< Type of descriptor */
	uint16_t descriptor_len;	/**< Length of descriptor */
	uint16_t descriptor_data;	/**< Data contained in the descriptor. */
};

/**
 * Measurement bit stream representing the device identifier information to use for attestation
 * discovery.
 */
struct spdm_discovery_device_id {
	struct spdm_discovery_device_id_block header;			/**< Header on the the descriptor list. */
	struct spdm_discovery_pci_id_descriptor descriptor[4];	/**< List of descriptor identifiers. */
};

#pragma pack(pop)


void spdm_discovery_device_id_init (struct spdm_discovery_device_id *discovery, uint16_t vendor_id,
	uint16_t device_id, uint16_t subsystem_vid, uint16_t subsystem_id);


#endif	/* SPDM_DISCOVERY_H_ */
