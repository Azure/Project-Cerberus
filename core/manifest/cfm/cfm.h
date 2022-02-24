// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CFM_H_
#define CFM_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "status/rot_status.h"
#include "manifest/manifest.h"
#include "manifest/cfm/cfm_format.h"


/**
 * CFM attestation protocols.
 */
enum cfm_attestation_type {
	CFM_ATTESTATION_CERBERUS_PROTOCOL = 0x00,					/**< Cerberus challenge protocol. */
	CFM_ATTESTATION_DMTF_SPDM = 0x01,							/**< DMTF SPDM protocol. */
};

/**
 * CFM data check types.
 */
enum cfm_check {
	CFM_CHECK_EQUAL = 0x00,										/**< Measurement equal to CFM value. */
	CFM_CHECK_NOT_EQUAL = 0x01,									/**< Measurement not equal to CFM value. */
	CFM_CHECK_LESS_THAN = 0x02,									/**< Measurement less than CFM value. */
	CFM_CHECK_LESS_OR_EQUAL = 0x03,								/**< Measurement less than or equal to CFM value. */
	CFM_CHECK_GREATER_THAN = 0x04,								/**< Measurement greater than CFM value. */
	CFM_CHECK_GREATER_THAN_OR_EQUAL = 0x05,						/**< Measurement greater than or equal to CFM value. */
};

/**
 * Information necessary to attest a component device.
 */
struct cfm_component_device {
	uint8_t cert_slot;											/**< Slot number of certificate chain to use for attestation challenges. */
	enum cfm_attestation_type attestation_protocol;				/**< Protocol to use for attestation requests to the component. */
	const char *type;											/**< Component type. */
	const uint8_t *pmr_id_list;									/**< List of PMR IDs of all PMR digest entries in CFM. */
	size_t num_pmr_digest;										/**< Number of PMR IDs in PMR digest list. */
};

/**
 * Common container for digests lists.
 */
struct cfm_digests {
	size_t hash_len;											/**< Digest length. */
	size_t digest_count;										/**< Number of digests in digests list. */
	const uint8_t *digests;										/**< Buffer holding list of digests. */
};

/**
 * Allowable digests for PMR ID.
 */
struct cfm_pmr_digest {
	uint8_t pmr_id;												/**< PMR ID. */
	struct cfm_digests digests;									/**< PMR allowable digests. */
};

/**
 * Allowable digests for a PMR measurement.
 */
struct cfm_measurement {
	void *context;												/**< Implementation context. */
	uint8_t pmr_id;												/**< PMR ID. */
	uint8_t measurement_id;										/**< PMR entry ID if Cerberus protocol, or measurement block index if SPDM. */
	struct cfm_digests digests;									/**< Allowable digests for PMR measurement. */
};

/**
 * A list of allowable data for a single PMR measurement check.
 */
struct cfm_allowable_data {
	enum cfm_check check;										/**< Checking method. */
	size_t data_count;											/**< Number of allowable data. */
	size_t data_len;											/**< Length of data to use for comparison. */
	const uint8_t *bitmask;										/**< Buffer holding bitmask, if present. */
	const uint8_t *allowable_data;								/**< Buffer holding list of allowable data. */
};

/**
 * Rules for performing attestation checks for a PMR measurement.
 */
struct cfm_measurement_data {
	void *context;												/**< Implementation context. */
	uint8_t pmr_id;												/**< PMR ID. */
	uint8_t measurement_id;										/**< Measurement ID. */
	size_t check_count;											/**< Number of allowable data checks. */
	struct cfm_allowable_data *check;							/**< List of allowable data check containers. */
};

/**
 * Allowable root CA digest list.
 */
struct cfm_root_ca_digests {
	struct cfm_digests digests;									/**< Allowable root CA digests. */
};

/**
 * Information necessary to recompute PMR digest using PMR measurements.
 */
struct cfm_pmr {
	uint8_t pmr_id;												/**< PMR ID. */
	size_t initial_value_len;									/**< Initial value length. */
	const uint8_t initial_value[SHA512_HASH_LENGTH];			/**< Buffer with initial PMR value. */
};

/**
 * A list of allowable IDs for a single manifest check.
 */
struct cfm_allowable_id {
	enum cfm_check check;										/**< Type of check to perform. */
	size_t id_count;											/**< Number of allowable IDs. */
	const uint32_t *allowable_id;								/**< Buffer holding list of allowable IDs. */
};

/**
 * Rules for performing attestation checks for a manifest.
 */
struct cfm_manifest {
	void *context;												/**< Implementation context. */
	uint8_t manifest_index;										/**< Port ID for PFMs and CFM index for CFMs. Not utilized for PCDs. */
	size_t check_count;											/**< Number of manifest checks. */
	const char *platform_id;									/**< Buffer holding the platform ID. */
	struct cfm_allowable_id *check;								/**< List of allowable ID check containers. */
};


/**
 * The API for interfacing with a cfm file.
 */
struct cfm {
	struct manifest base;										/**< Manifest interface */

	/**
	 * Find component device for the specified component type.
	 *
	 * @param cfm The CFM to query.
	 * @param component_type The component type to find.
	 * @param component Output for the component device data.
	 *
	 * @return 0 if the component device was found or an error code.
	 */
	int (*get_component_device) (struct cfm *cfm, const char *component_type,
		struct cfm_component_device *component);

	/**
	 * Free content within a component device container.
	 *
	 * @param cfm The CFM instance that provided the component device.
	 * @param component The component device container with content to free.
	 */
	void (*free_component_device) (struct cfm *cfm, struct cfm_component_device *component);

	/**
	 * Get list of supported component types from CFM.
	 *
	 * @param cfm The CFM to query.
	 * @param offset The offset within the overall list of supported component types that should be
	 * returned.
	 * @param length The maximum length of component types information that should be returned.
	 * @param components Output buffer for the list of supported component types.
	 *
	 * @return The number of bytes written to the output buffer or an error code.  Use ROT_IS_ERROR
	 * to check the return value.
	 */
	int (*buffer_supported_components) (struct cfm *cfm, size_t offset, size_t length,
		uint8_t *components);

	/**
	 * Get PMR container for provided component type and PMR ID
	 *
	 * @param cfm The CFM to query.
	 * @param component_type The component type to query.
	 * @param pmr_id The PMR ID to query.
	 * @param pmr A container to be updated with the component PMR information.
	 *
	 * @return 0 if the component PMR was retrieved successfully or an error code.
	 */
	int (*get_component_pmr) (struct cfm *cfm, const char *component_type, uint8_t pmr_id,
		struct cfm_pmr *pmr);

	/**
	 * Get component PMR digest container for provided component type and PMR ID
	 *
	 * @param cfm The CFM to query.
	 * @param component_type The component type to query.
	 * @param pmr_id The PMR ID to query.
	 * @param pmr_digest A container to be updated with the component PMR digest information.
	 *
	 * @return 0 if the component PMR digest was retrieved successfully or an error code.
	 */
	int (*get_component_pmr_digest) (struct cfm *cfm, const char *component_type, uint8_t pmr_id,
		struct cfm_pmr_digest *pmr_digest);

	/**
	 * Free content within a component pmr digest container.
	 *
	 * @param cfm The CFM instance that provided the PMR digest.
	 * @param pmr_digest The PMR digest container with content to free.
	 */
	void (*free_component_pmr_digest) (struct cfm *cfm, struct cfm_pmr_digest *pmr_digest);

	/**
	 * Find next measurement for the specified component type.
	 *
	 * @param cfm The CFM to query.
	 * @param component_type The component type to find a measurement for.
	 * @param pmr_measurement A container to be updated with the component measurement information.
	 * @param first Fetch first PMR measurement from CFM, or next PMR measurement since last call.
	 *
	 * @return 0 if the measurement was found or an error code.
	 */
	int (*get_next_measurement) (struct cfm *cfm, const char *component_type,
		struct cfm_measurement *pmr_measurement, bool first);

	/**
	 * Free content within a measurement container.
	 *
	 * @param cfm The CFM instance that provided the measurement.
	 * @param pmr_measurement The measurement container with content to free.
	 */
	void (*free_measurement) (struct cfm *cfm, struct cfm_measurement *pmr_measurement);

	/**
	 * Find next measurement data for the specified component type.
	 *
	 * @param cfm The CFM to query.
	 * @param component_type The component type to find a measurement data for.
	 * @param measurement_data A container to be updated with the component measurement data
	 * 	information.
	 * @param first Fetch first measurement data from CFM, or next measurement data since last call.
	 *
	 * @return 0 if the measurement data was found or an error code.
	 */
	int (*get_next_measurement_data) (struct cfm *cfm, const char *component_type,
		struct cfm_measurement_data *measurement_data, bool first);

	/**
	 * Free content within a measurement data container.
	 *
	 * @param cfm The CFM instance that provided the measurement data.
	 * @param measurement_data The measurement data container with content to free.
	 */
	void (*free_measurement_data) (struct cfm *cfm, struct cfm_measurement_data *measurement_data);

	/**
	 * Find root CA digest for the specified component type.
	 *
	 * @param cfm The CFM to query.
	 * @param component_type The component type to find root CA digest for.
	 * @param root_ca_digest A container to be updated with the component root CA digest
	 * 	information.
	 *
	 * @return 0 if the root CA digest was found or an error code.
	 */
	int (*get_root_ca_digest) (struct cfm *cfm, const char *component_type,
		struct cfm_root_ca_digests *root_ca_digest);

	/**
	 * Free content within a root CA digests container.
	 *
	 * @param cfm The CFM instance that provided the root CA digests.
	 * @param root_ca_digest The root CA digests container with content to free.
	 */
	void (*free_root_ca_digest) (struct cfm *cfm, struct cfm_root_ca_digests *root_ca_digest);

	/**
	 * Find next allowable PFM for the specified component type.
	 *
	 * @param cfm The CFM to query.
	 * @param component_type The component type to find allowable PFM for.
	 * @param allowable_pfm A container to be updated with the component allowable PFM information.
	 * @param first Fetch first allowable PFM from CFM, or next allowable PFM since last call.
	 *
	 * @return 0 if the allowable PFM was found or an error code.
	 */
	int (*get_next_pfm) (struct cfm *cfm, const char *component_type,
		struct cfm_manifest *allowable_pfm, bool first);

	/**
	 * Find next allowable CFM for the specified component type.
	 *
	 * @param cfm The CFM to query.
	 * @param component_type The component type to find allowable CFM for.
	 * @param allowable_cfm A container to be updated with the component allowable CFM information.
	 * @param first Fetch first allowable CFM from CFM, or next allowable CFM since last call.
	 *
	 * @return 0 if the allowable CFM was found or an error code.
	 */
	int (*get_next_cfm) (struct cfm *cfm, const char *component_type,
		struct cfm_manifest *allowable_cfm, bool first);

	/**
	 * Find allowable PCD for the specified component type.
	 *
	 * @param cfm The CFM to query.
	 * @param component_type The component type to find allowable PCD for.
	 * @param allowable_pcd A container to be updated with the component allowable PCD information.
	 *
	 * @return 0 if the allowable PCD was found or an error code.
	 */
	int (*get_pcd) (struct cfm *cfm, const char *component_type,
		struct cfm_manifest *allowable_pcd);

	/**
	 * Free content within a manifest container.
	 *
	 * @param cfm The CFM instance that provided the manifest.
	 * @param manifest The manifest container with content to free.
	 */
	void (*free_manifest) (struct cfm *cfm, struct cfm_manifest *manifest);
};


#define	CFM_ERROR(code)		ROT_ERROR (ROT_MODULE_CFM, code)

/**
 * Error codes that can be generated by a CFM.
 */
enum {
	CFM_INVALID_ARGUMENT = CFM_ERROR (0x00),				/**< Input parameter is null or not valid. */
	CFM_NO_MEMORY = CFM_ERROR (0x01),						/**< Memory allocation failed. */
	CFM_PMR_DIGEST_NOT_FOUND = CFM_ERROR (0x02),			/**< CFM does not contain allowable PMR digests for PMR ID provided. */
	CFM_MEASUREMENT_NOT_FOUND = CFM_ERROR (0x03),			/**< Could not find measurement for component type in CFM. */
	CFM_MEASUREMENT_DATA_NOT_FOUND = CFM_ERROR (0x04),		/**< Could not find measurement data for component type in CFM. */
	CFM_ROOT_CA_NOT_FOUND = CFM_ERROR (0x05),				/**< Could not find root CA digest for component type in CFM. */
	CFM_ELEMENT_NOT_FOUND = CFM_ERROR (0x06),				/**< Could not find requested element for component type in CFM. */
	CFM_PMR_NOT_FOUND = CFM_ERROR (0x07),					/**< CFM does not contain PMR for PMR ID provided. */
	CFM_ELEMENT_MISSING_DIGESTS = CFM_ERROR (0x08),			/**< CFM element missing expected digests list. */
	CFM_GET_COMP_DEVICE_FAIL = CFM_ERROR (0x09),			/**< Retrieving component device failed. */
	CFM_BUFFER_SUPPORTED_COMP_FAIL = CFM_ERROR (0x0A),		/**< The list of supported components was not generated. */
	CFM_GET_COMP_PMR_FAIL = CFM_ERROR (0x0B),				/**< Retrieving component PMR failed. */
	CFM_GET_COMP_PMR_DIGEST_FAIL = CFM_ERROR (0x0C),		/**< Retrieving component PMR digest failed. */
	CFM_GET_NEXT_MEASUREMENT_FAIL = CFM_ERROR (0x0D),		/**< Retrieving next allowable measurement failed. */
	CFM_GET_NEXT_MEASUREMENT_DATA_FAIL = CFM_ERROR (0x0E),	/**< Retrieving next allowable measurement data failed. */
	CFM_GET_ROOT_CA_DIGEST_FAIL = CFM_ERROR (0x0F),			/**< Retrieving list of root CA digests failed. */
	CFM_GET_NEXT_PFM_FAIL = CFM_ERROR (0x10),				/**< Retrieving next allowable PFM failed. */
	CFM_GET_NEXT_CFM_FAIL = CFM_ERROR (0x11),				/**< Retrieving next allowable CFM failed. */
	CFM_GET_PCD_FAIL = CFM_ERROR (0x12),					/**< Retrieving allowable PCD failed. */
};


#endif /* CFM_H_ */
