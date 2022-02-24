// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CFM_FORMAT_H_
#define CFM_FORMAT_H_

#include <stdint.h>
#include "manifest/manifest_format.h"

/**
 * Type identifiers for CFM v2 elements.
 */
enum cfm_element_type {
	CFM_COMPONENT_DEVICE = 0x70,								/**< Information about each component to attest. */
	CFM_PMR = 0x71,												/**< Information for PMRs that can be used for PMR generation. */
	CFM_PMR_DIGEST = 0x72,										/**< Information about all allowable digests for a single PMR. */
	CFM_MEASUREMENT = 0x73,										/**< Information about all allowable digests for a single measurement. */
	CFM_MEASUREMENT_DATA = 0x74,								/**< Information about all allowable data for a single measurement. */
	CFM_ALLOWABLE_DATA = 0x75,									/**< List of allowable data for a single measurement data check. */
	CFM_ALLOWABLE_PFM = 0x76,									/**< Information for allowable PFM IDs. */
	CFM_ALLOWABLE_CFM = 0x77,									/**< Information for allowable CFM IDs. */
	CFM_ALLOWABLE_PCD = 0x78,									/**< Information for allowable PCD IDs. */
	CFM_ALLOWABLE_ID = 0x79,									/**< List of allowable IDs for a single manifest ID check. */
	CFM_ROOT_CA = 0x7A,											/**< Information for external Root CAs that can be used for certificate chain validation. */
};

/**
 * CFM data check types.
 */
enum cfm_check_type {
	CFM_EQUAL = 0x00,											/**< Measurement equal to CFM value. */
	CFM_NOT_EQUAL = 0x01,										/**< Measurement not equal to CFM value. */
	CFM_LESS_THAN = 0x02,										/**< Measurement less than CFM value. */
	CFM_LESS_OR_EQUAL = 0x03,									/**< Measurement less than or equal to CFM value. */
	CFM_GREATER_THAN = 0x04,									/**< Measurement greater than CFM value. */
	CFM_GREATER_THAN_OR_EQUAL = 0x05,							/**< Measurement greater than or equal to CFM value. */
};

/**
 * CFM attestation protocols.
 */
enum cfm_attestation_protocol {
	CFM_CERBERUS_PROTOCOL = 0x00,								/**< Cerberus challenge protocol. */
	CFM_DMTF_SPDM = 0x01,										/**< DMTF SPDM protocol. */
};


#pragma pack(push, 1)
/**
 * CFM component device element.
 */
struct cfm_component_device_element {
	uint8_t cert_slot;											/**< Slot number of certificate chain to use for attestation challenges. */
	uint8_t attestation_protocol;								/**< Protocol to use for attestation requests to the component. */
	uint8_t reserved;											/**< Reserved. */
	uint8_t type_len;											/**< Component type length. */
	uint8_t type[MANIFEST_MAX_STRING];							/**< Component type. */
};

/**
 * CFM platform measurement register digest element.
 */
struct cfm_pmr_digest_element {
	uint8_t pmr_id;												/**< PMR ID. */
	uint8_t reserved:5;											/**< Reserved. */
	uint8_t pmr_hash_type:3;									/**< PMR hash type. */
	uint8_t digest_count;										/**< Number of allowable digests for this PMR. */
	uint8_t reserved2;											/**< Reserved. */
};

/**
 * CFM measurement element.
 */
struct cfm_measurement_element {
	uint8_t pmr_id;												/**< PMR ID. */
	uint8_t measurement_id;										/**< PMR entry ID if Cerberus protocol, or measurement block index if SPDM. */
	uint8_t reserved:5;											/**< Reserved. */
	uint8_t hash_type:3;										/**< Hash type. */
	uint8_t digest_count;										/**< Number of allowable digests for this measurement. */
};

/**
 * CFM measurement data element.
 */
struct cfm_measurement_data_element {
	uint8_t pmr_id;												/**< PMR ID. */
	uint8_t measurement_id;										/**< Measurement ID. */
	uint16_t reserved;											/**< Reserved. */
};

/**
 * CFM allowable data element.
 */
struct cfm_allowable_data_element {
	uint8_t reserved:7;											/**< Reserved. */
	uint8_t bitmask_presence:1;									/**< Flag indicating presence of a bitmask. */
	uint8_t check;												/**< Checking method. */
	uint8_t num_data;											/**< Number of allowable data. */
	uint16_t data_len;											/**< Length of data to use for comparison. */
	uint8_t reserved2[3];										/**< Reserved. */
};

/**
 * Common segment for allowable manifest elements.
 */
struct cfm_allowable_manifest {
	uint8_t platform_id_len;									/**< Platform ID length. */
	uint8_t platform_id[MANIFEST_MAX_STRING];					/**< Platform ID. */
};

/**
 * A allowable PFM element.
 */
struct cfm_allowable_pfm_element {
	uint8_t port_id;											/**< Port ID. */
	struct cfm_allowable_manifest manifest;						/**< Allowable manifest segment. */
};

/**
 * A allowable CFM element.
 */
struct cfm_allowable_cfm_element {
	uint8_t index;												/**< CFM index. */
	struct cfm_allowable_manifest manifest;						/**< Allowable manifest segment. */
};

/**
 * A allowable PCD element.
 */
struct cfm_allowable_pcd_element {
	uint8_t reserved;											/**< Reserved. */
	struct cfm_allowable_manifest manifest;						/**< Allowable manifest segment. */
};

/**
 * A allowable ID element.
 */
struct cfm_allowable_id_element {
	uint8_t check;												/**< The type of comparison to execute. */
	uint8_t num_id;												/**< Number of alllowable IDs. */
	uint16_t reserved;											/**< Reserved. */
};

/**
 * CFM root CA digests element.
 */
struct cfm_root_ca_digests_element {
	uint8_t reserved:5;											/**< Reserved. */
	uint8_t hash_type:3;										/**< Hash type. */
	uint8_t ca_count;											/**< Number of allowable root CA digests. */
	uint16_t reserved2;											/**< Reserved. */
};

/**
 * CFM PMR element.
 */
struct cfm_pmr_element {
	uint8_t pmr_id;												/**< PMR ID. */
	uint8_t reserved:5;											/**< Reserved. */
	uint8_t hash_type:3;										/**< Hash type. */
	uint16_t reserved2;											/**< Reserved. */
	uint8_t initial_value[SHA512_HASH_LENGTH];					/**< Initial value to use when generating PMR. */
};

#pragma pack(pop)


#endif /* CFM_FORMAT_H_ */
