// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_MEASUREMENTS_H_
#define SPDM_MEASUREMENTS_H_

#include <stdint.h>
#include "attestation/pcr.h"


// SPDM DMTF measurement block format
#define SPDM_MEASUREMENTS_BLOCK_DMTF_SPEC_FORMAT					(1 << 0)

// Device ID block success completion code
#define SPDM_MEASUREMENTS_DEVICE_ID_BLOCK_CC_SUCCESS				(0x00)

/**
 * Get the total length of a SPDM measurement block
 *
 * @param measurement_size Size of measurement in measurement block
 */
#define spdm_measurements_block_size(measurement_size)				(sizeof (struct spdm_measurements_block_header) + measurement_size)

/**
 * Get the total length of a SPDM measurement block with a PCR digest
 */
#define SPDM_MEASUREMENTS_DIGEST_BLOCK_LEN							(spdm_measurements_block_size (PCR_DIGEST_LENGTH))


/**
 * SPDM Device ID descriptors
 */
enum spdm_measurement_device_id_descriptors {
	SPDM_MEASUREMENTS_DEVICE_ID_PCI_VID = 0x0000,					/**< PCI Vendor ID */
	SPDM_MEASUREMENTS_DEVICE_ID_IANA_ENTERPRISE_ID = 0x0001,		/**< IANA Enterprise ID */
	SPDM_MEASUREMENTS_DEVICE_ID_UUID = 0x0002,						/**< UUID */
	SPDM_MEASUREMENTS_DEVICE_ID_PNP_VID = 0x0003,					/**< PnP Vendor ID */
	SPDM_MEASUREMENTS_DEVICE_ID_ACPI_VID = 0x0004,					/**< ACPI Vendor ID */
	SPDM_MEASUREMENTS_DEVICE_ID_IEEE_COMPANY_ID = 0x0005,			/**< IEEE Assigned Company ID */
	SPDM_MEASUREMENTS_DEVICE_ID_SCSI_VID = 0x0006,					/**< SCSI Vendor ID */
	SPDM_MEASUREMENTS_DEVICE_ID_PCI_DEVICE_ID = 0x0100,				/**< PCI Device ID */
	SPDM_MEASUREMENTS_DEVICE_ID_PCI_SUBSYSTEM_VID = 0x0101,			/**< PCI Subsystem Vendor ID */
	SPDM_MEASUREMENTS_DEVICE_ID_PCI_SUBSYSTEM_ID = 0x0102,			/**< PCI Subsystem ID */
	SPDM_MEASUREMENTS_DEVICE_ID_PCI_REVISION_ID = 0x0103,			/**< PCI Revision ID */
	SPDM_MEASUREMENTS_DEVICE_ID_PNP_PRODUCT_ID = 0x0104,			/**< PnP Product ID */
	SPDM_MEASUREMENTS_DEVICE_ID_ACPI_PRODUCT_ID = 0x0105,			/**< ACPI Product ID */
	SPDM_MEASUREMENTS_DEVICE_ID_ASCII_MODEL_NUM_LONG_STR = 0x0106,	/**< ASCII Model Number (Long String) */
	SPDM_MEASUREMENTS_DEVICE_ID_ASCII_MODEL_NUM_SHORT_STR = 0x0107,	/**< ASCII Model Number (Short String) */
	SPDM_MEASUREMENTS_DEVICE_ID_SCSI_PRODUCT_ID = 0x0108,			/**< SCSI Product ID */
	SPDM_MEASUREMENTS_DEVICE_ID_UBM_CONTROLLER_DEVICE_CODE = 0x0106,/**< UBM Controller Device Code */
	SPDM_MEASUREMENTS_DEVICE_ID_VENDOR_DEFINED = 0xFFFF,			/**< Vendor Defined */
};

/**
 * Header for a measurement portion of measurement block following DMTF format. Defined in the SPDM
 * DSP0274 spec section 10.11.1.1.
 */
struct spdm_measurements_block_dmtf {
	uint8_t measurement_block_type:7;								/**< The type of data being measured */
	uint8_t raw_bit_stream:1;										/**< Flag indicating whether data is in raw or digest form */
	uint16_t measurement_size;										/**< Size of measurement block */
};

/**
 * Header for a measurement block. Defined in the SPDM DSP0274 spec section 10.11.1.
 */
struct spdm_measurements_block_header {
	uint8_t index;													/**< Measurement block index */
	uint8_t measurement_specification;								/**< Measurement specification the measurement block format follows */
	uint16_t measurement_size;										/**< Size of following portion of the measurement block */
	struct spdm_measurements_block_dmtf dmtf;						/**< Measurement following DMTF format */
};

/**
 * Format of a device ID measurement block.  This is a custom measurement block format based on the
 * PLDM QueryDeviceIdentifiers command used to address device ID discovery gap in SPDM 1.1 and 1.2.
 * Later versions of the SPDM specification is expected to address this gap, so this block should be
 * only used in earlier SPDM specification versions.
 */
struct spdm_measurements_device_id_block {
	uint8_t completion_code;										/**< Completion code */
	uint32_t device_id_len;											/**< Total length of descriptors field */
	uint8_t descriptor_count;										/**< Number of descriptors in descriptors field */
};

/** Format of a device ID descriptor.
 */
struct spdm_measurements_device_id_descriptor {
	uint16_t descriptor_type;										/**< Type of descriptor */
	uint16_t descriptor_len;										/**< Length of descriptor */
};


#endif // SPDM_MEASUREMENTS_H_
