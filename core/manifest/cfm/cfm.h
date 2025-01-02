// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CFM_H_
#define CFM_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "manifest/cfm/cfm_format.h"
#include "manifest/manifest.h"
#include "status/rot_status.h"


/**
 * CFM attestation protocols.
 */
enum cfm_attestation_type {
	CFM_ATTESTATION_CERBERUS_PROTOCOL = 0x00,	/**< Cerberus challenge protocol. */
	CFM_ATTESTATION_DMTF_SPDM = 0x01,			/**< DMTF SPDM protocol. */
};

/**
 * CFM data check types.
 */
enum cfm_check {
	CFM_CHECK_EQUAL = 0x00,					/**< Measurement equal to CFM value. */
	CFM_CHECK_NOT_EQUAL = 0x01,				/**< Measurement not equal to CFM value. */
	CFM_CHECK_LESS_THAN = 0x02,				/**< Measurement less than CFM value. */
	CFM_CHECK_LESS_THAN_OR_EQUAL = 0x03,	/**< Measurement less than or equal to CFM value. */
	CFM_CHECK_GREATER_THAN = 0x04,			/**< Measurement greater than CFM value. */
	CFM_CHECK_GREATER_THAN_OR_EQUAL = 0x05,	/**< Measurement greater than or equal to CFM value. */
};

/**
 * CFM measurement entry types.
 */
enum cfm_measurement_type {
	CFM_MEASUREMENT_TYPE_DIGEST = 0x00,	/**< Measurement entry. */
	CFM_MEASUREMENT_TYPE_DATA = 0x01,	/**< Measurement data entry. */
};

/**
 * Information necessary to attest a component device.
 */
struct cfm_component_device {
	uint8_t cert_slot;								/**< Slot number of certificate chain to use for attestation challenges. */
	enum cfm_attestation_type attestation_protocol;	/**< Protocol to use for attestation requests to the component. */
	enum hash_type transcript_hash_type;			/**< Hash type used for SPDM transcript hashing. */
	enum hash_type measurement_hash_type;			/**< Hash type used to generate measurement, PMR, and root CA digests. */
	uint32_t component_id;							/**< Unique identifier for component type. */
	const uint8_t *pmr_id_list;						/**< List of PMR IDs of all PMR digest entries in CFM. */
	size_t num_pmr_ids;								/**< Number of PMR IDs in PMR digest list. */
};

/**
 * Common container for digests lists.
 */
struct cfm_digests {
	enum hash_type hash_type;	/**< Hash algorithm type. */
	size_t digest_count;		/**< Number of digests in digests list. */
	const uint8_t *digests;		/**< Buffer holding list of digests. */
};

/**
 * Container for allowable digests lists.
 */
struct cfm_allowable_digests {
	uint16_t version_set;		/**< Identifier for set of measurements associated with the same device firmware version. 0 if set applies to all versions. */
	struct cfm_digests digests;	/**< Container holding allowable digests. */
};

/**
 * Allowable digests for PMR ID.
 */
struct cfm_pmr_digest {
	uint8_t pmr_id;				/**< PMR ID. */
	struct cfm_digests digests;	/**< PMR allowable digests. */
};

/**
 * Allowable digests for a PMR measurement.
 */
struct cfm_measurement_digest {
	uint8_t pmr_id;										/**< PMR ID. */
	uint8_t measurement_id;								/**< PMR entry ID if Cerberus protocol, or measurement block index if SPDM. */
	size_t allowable_digests_count;						/**< Number of allowable digests in allowable digests list. */
	struct cfm_allowable_digests *allowable_digests;	/**< List of allowable digest containers for PMR measurement. */
};

/**
 * An individual data entry within an allowable data container.
 */
struct cfm_allowable_data_entry {
	uint16_t version_set;	/**< Identifier for set of measurements associated with the same device firmware version. 0 if set applies to all versions. */
	uint16_t data_len;		/**< Length of the data. */
	const uint8_t *data;	/**< Data to use for comparison. */
};

/**
 * A list of allowable data for a single PMR measurement check.
 */
struct cfm_allowable_data {
	enum cfm_check check;								/**< Type of check to perform. */
	bool big_endian;									/**< Flag indicating if data is in big endian. */
	size_t data_count;									/**< Number of allowable data. */
	size_t bitmask_length;								/**< Length of bitmask. */
	const uint8_t *bitmask;								/**< Buffer holding bitmask, if present. */
	struct cfm_allowable_data_entry *allowable_data;	/**< List of allowable data entry containers. */
};

/**
 * Rules for performing attestation checks for a PMR measurement.
 */
struct cfm_measurement_data {
	uint8_t pmr_id;							/**< PMR ID. */
	uint8_t measurement_id;					/**< Measurement ID. */
	size_t data_checks_count;				/**< Number of allowable data checks. */
	struct cfm_allowable_data *data_checks;	/**< List of allowable data check containers. */
};

/**
 * Combined measurement and measurement data container.
 */
struct cfm_measurement_container {
	void *context;								/**< Implementation context.*/
	union {
		struct cfm_measurement_digest digest;	/**< Measurement digest container. */
		struct cfm_measurement_data data;		/**< Measurement data container. */
	} measurement;
	enum cfm_measurement_type measurement_type;	/**< Measurement entry retrieved. */
};

/**
 * Allowable root CA digest list.
 */
struct cfm_root_ca_digests {
	struct cfm_digests digests;	/**< Allowable root CA digests. */
};

/**
 * Information necessary to recompute PMR digest using PMR measurements.
 */
struct cfm_pmr {
	uint8_t pmr_id;										/**< PMR ID. */
	size_t initial_value_len;							/**< Initial value length. */
	enum hash_type hash_type;							/**< Hash algorithm type. */
	const uint8_t initial_value[SHA512_HASH_LENGTH];	/**< Buffer with initial PMR value. */
};

/**
 * A list of allowable IDs for a single manifest check.
 */
struct cfm_allowable_id {
	enum cfm_check check;			/**< Type of check to perform. */
	size_t id_count;				/**< Number of allowable IDs. */
	const uint32_t *allowable_id;	/**< Buffer holding list of allowable IDs. */
};

/**
 * Rules for performing attestation checks for a manifest.
 */
struct cfm_manifest {
	void *context;					/**< Implementation context. */
	uint8_t manifest_index;			/**< Port ID for PFMs and CFM index for CFMs. Not utilized for PCDs. */
	size_t check_count;				/**< Number of manifest checks. */
	const char *platform_id;		/**< Buffer holding the platform ID. */
	struct cfm_allowable_id *check;	/**< List of allowable ID check containers. */
};


/**
 * The API for interfacing with a cfm file.
 */
struct cfm {
	struct manifest base;	/**< Manifest interface */

	/**
	 * Find component device for the specified component ID.
	 *
	 * @param cfm The CFM to query.
	 * @param component_id The component ID to find.
	 * @param component Output for the component device data.
	 *
	 * @return 0 if the component device was found or an error code.
	 */
	int (*get_component_device) (const struct cfm *cfm, uint32_t component_id,
		struct cfm_component_device *component);

	/**
	 * Free content within a component device container.
	 *
	 * @param cfm The CFM instance that provided the component device.
	 * @param component The component device container with content to free.
	 */
	void (*free_component_device) (const struct cfm *cfm, struct cfm_component_device *component);

	/**
	 * Get list of supported component IDs from CFM.
	 *
	 * @param cfm The CFM to query.
	 * @param offset The byte offset within the overall list of supported component IDs that should
	 * 	be returned.
	 * @param length The maximum length of component ID information that should be returned, in
	 * 	bytes.
	 * @param component_ids Output buffer for the list of supported component IDs.
	 *
	 * @return The number of bytes written to the output buffer or an error code.  Use ROT_IS_ERROR
	 * to check the return value.
	 */
	int (*buffer_supported_components) (const struct cfm *cfm, size_t offset, size_t length,
		uint8_t *component_ids);

	/**
	 * Get PMR container for provided component ID and PMR ID
	 *
	 * @param cfm The CFM to query.
	 * @param component_id The component ID to query.
	 * @param pmr_id The PMR ID to query.
	 * @param pmr A container to be updated with the component PMR information.
	 *
	 * @return 0 if the component PMR was retrieved successfully or an error code.
	 */
	int (*get_component_pmr) (const struct cfm *cfm, uint32_t component_id, uint8_t pmr_id,
		struct cfm_pmr *pmr);

	/**
	 * Get component PMR digest container for provided component ID and PMR ID
	 *
	 * @param cfm The CFM to query.
	 * @param component_id The component ID to query.
	 * @param pmr_id The PMR ID to query.
	 * @param pmr_digest A container to be updated with the component PMR digest information.
	 *
	 * @return 0 if the component PMR digest was retrieved successfully or an error code.
	 */
	int (*get_component_pmr_digest) (const struct cfm *cfm, uint32_t component_id, uint8_t pmr_id,
		struct cfm_pmr_digest *pmr_digest);

	/**
	 * Free content within a component pmr digest container.
	 *
	 * @param cfm The CFM instance that provided the PMR digest.
	 * @param pmr_digest The PMR digest container with content to free.
	 */
	void (*free_component_pmr_digest) (const struct cfm *cfm, struct cfm_pmr_digest *pmr_digest);

	/**
	 * Find the next Measurement Digest or Measurement Data for the specified component ID.  When
	 * first is equal to true, this must return the Measurement information that will be used to
	 * determine the current version set of Measurements.
	 *
	 * If free_measurement_container is called on a measurement, the next call to this function must
	 * set first to true.  It is necessary to call free_measurement_container on the output
	 * container before making another call with first set to true.  The exception is when a call
	 * with first set to true fails.  In this case, free_measurement_container can still safely be
	 * called, but is not strictly required.
	 *
	 * @param cfm The CFM to query.
	 * @param component_id The component ID to find entry for.
	 * @param container A container to be updated with the found component measurement information.
	 *  Output will have either Measurement or Measurement Data, or neither if no entry is found.
	 * 	If first is not true, then same container that was passed previously needs to be passed in.
	 * 	Instances never passed to this function need to have first set to true.
	 * @param first Fetch measurement or measurement data from CFM, or next since last call.
	 *
	 * @return 0 if the Measurement or Measurement Data was found or an error code.
	 */
	int (*get_next_measurement_or_measurement_data) (const struct cfm *cfm, uint32_t component_id,
		struct cfm_measurement_container *container, bool first);

	/**
	 * Free content within a measurement container.  Calls to this function when a container has
	 * already been freed are allowed.
	 *
	 * @param cfm The CFM instance that provided the measurement.
	 * @param container The measurement container with content to free.
	 */
	void (*free_measurement_container) (const struct cfm *cfm,
		struct cfm_measurement_container *container);

	/**
	 * Find root CA digest for the specified component ID.
	 *
	 * @param cfm The CFM to query.
	 * @param component_id The component ID to find root CA digest for.
	 * @param root_ca_digest A container to be updated with the component root CA digest
	 * 	information.
	 *
	 * @return 0 if the root CA digest was found or an error code.
	 */
	int (*get_root_ca_digest) (const struct cfm *cfm, uint32_t component_id,
		struct cfm_root_ca_digests *root_ca_digest);

	/**
	 * Free content within a root CA digests container.
	 *
	 * @param cfm The CFM instance that provided the root CA digests.
	 * @param root_ca_digest The root CA digests container with content to free.
	 */
	void (*free_root_ca_digest) (const struct cfm *cfm, struct cfm_root_ca_digests *root_ca_digest);

	/**
	 * Find next allowable PFM for the specified component ID.
	 *
	 * If free_manifest is called on a manifest container, the next call to this function must
	 * set first to true.  It is necessary to call free_manifest on the output
	 * container before making another call with first set to true.  The exception is when a call
	 * with first set to true fails.  In this case, free_manifest can still safely be
	 * called, but is not strictly required.
	 *
	 * @param cfm The CFM to query.
	 * @param component_id The component ID to find allowable PFM for.
	 * @param allowable_pfm A container to be updated with the component allowable PFM information.
	 * 	If first is not	true, then same container that was passed previously needs to be passed in.
	 * 	Instances never	passed to this function need to have first set to true.
	 * @param first Fetch first allowable PFM from CFM, or next allowable PFM since last call.
	 *
	 * @return 0 if the allowable PFM was found or an error code.
	 */
	int (*get_next_pfm) (const struct cfm *cfm, uint32_t component_id,
		struct cfm_manifest *allowable_pfm, bool first);

	/**
	 * Find next allowable CFM for the specified component ID.
	 *
	 * If free_manifest is called on a manifest container, the next call to this function must
	 * set first to true.  It is necessary to call free_manifest on the output
	 * container before making another call with first set to true.  The exception is when a call
	 * with first set to true fails.  In this case, free_manifest can still safely be
	 * called, but is not strictly required.
	 *
	 * @param cfm The CFM to query.
	 * @param component_id The component ID to find allowable CFM for.
	 * @param allowable_cfm A container to be updated with the component allowable CFM information.
	 * 	If first is not	true, then same container that was passed previously needs to be passed in.
	 * 	Instances never	passed to this function need to have first set to true.
	 * @param first Fetch first allowable CFM from CFM, or next allowable CFM since last call.
	 *
	 * @return 0 if the allowable CFM was found or an error code.
	 */
	int (*get_next_cfm) (const struct cfm *cfm, uint32_t component_id,
		struct cfm_manifest *allowable_cfm, bool first);

	/**
	 * Find allowable PCD for the specified component ID.
	 *
	 * @param cfm The CFM to query.
	 * @param component_id The component ID to find allowable PCD for.
	 * @param allowable_pcd A container to be updated with the component allowable PCD information.
	 *
	 * @return 0 if the allowable PCD was found or an error code.
	 */
	int (*get_pcd) (const struct cfm *cfm, uint32_t component_id,
		struct cfm_manifest *allowable_pcd);

	/**
	 * Free content within a manifest container.  Calls to this function when a container has
	 * already been freed are allowed.
	 *
	 * @param cfm The CFM instance that provided the manifest.
	 * @param manifest The manifest container with content to free.
	 */
	void (*free_manifest) (const struct cfm *cfm, struct cfm_manifest *manifest);
};


#define	CFM_ERROR(code)		ROT_ERROR (ROT_MODULE_CFM, code)

/**
 * Error codes that can be generated by a CFM.
 */
enum {
	CFM_INVALID_ARGUMENT = CFM_ERROR (0x00),					/**< Input parameter is null or not valid. */
	CFM_NO_MEMORY = CFM_ERROR (0x01),							/**< Memory allocation failed. */
	CFM_PMR_DIGEST_NOT_FOUND = CFM_ERROR (0x02),				/**< CFM does not contain allowable PMR digests for PMR ID provided. */
	CFM_ROOT_CA_NOT_FOUND = CFM_ERROR (0x03),					/**< Could not find root CA digest for component type in CFM. */
	CFM_ENTRY_NOT_FOUND = CFM_ERROR (0x04),						/**< Could not find requested entry for component type in CFM. */
	CFM_PMR_NOT_FOUND = CFM_ERROR (0x05),						/**< CFM does not contain PMR for PMR ID provided. */
	CFM_ENTRY_MISSING_DIGESTS = CFM_ERROR (0x06),				/**< CFM entry missing expected digests list. */
	CFM_GET_COMP_DEVICE_FAIL = CFM_ERROR (0x07),				/**< Retrieving component device failed. */
	CFM_BUFFER_SUPPORTED_COMP_FAIL = CFM_ERROR (0x08),			/**< The list of supported components was not generated. */
	CFM_GET_COMP_PMR_FAIL = CFM_ERROR (0x09),					/**< Retrieving component PMR failed. */
	CFM_GET_COMP_PMR_DIGEST_FAIL = CFM_ERROR (0x0A),			/**< Retrieving component PMR digest failed. */
	CFM_GET_NEXT_MEASUREMENT_FAIL = CFM_ERROR (0x0B),			/**< Retrieving next allowable measurement failed. */
	CFM_GET_ROOT_CA_DIGEST_FAIL = CFM_ERROR (0x0C),				/**< Retrieving list of root CA digests failed. */
	CFM_GET_NEXT_PFM_FAIL = CFM_ERROR (0x0D),					/**< Retrieving next allowable PFM failed. */
	CFM_GET_NEXT_CFM_FAIL = CFM_ERROR (0x0E),					/**< Retrieving next allowable CFM failed. */
	CFM_GET_PCD_FAIL = CFM_ERROR (0x0F),						/**< Retrieving allowable PCD failed. */
	CFM_MALFORMED_COMPONENT_DEVICE_ENTRY = CFM_ERROR (0x10),	/**< CFM Component Device entry too short. */
	CFM_MALFORMED_PMR_DIGEST_ENTRY = CFM_ERROR (0x11),			/**< CFM PMR Digest entry too short. */
	CFM_MALFORMED_ALLOWABLE_DATA_ENTRY = CFM_ERROR (0x12),		/**< CFM Allowable Data entry too short. */
	CFM_MALFORMED_ALLOWABLE_ID_ENTRY = CFM_ERROR (0x13),		/**< CFM Allowable ID entry too short. */
	CFM_MALFORMED_PMR_ENTRY = CFM_ERROR (0x14),					/**< CFM PMR entry too short. */
	CFM_MALFORMED_MEASUREMENT_ENTRY = CFM_ERROR (0x15),			/**< CFM Measurement entry too short. */
	CFM_MALFORMED_MEASUREMENT_DATA_ENTRY = CFM_ERROR (0x16),	/**< CFM Measurement Data entry too short. */
	CFM_MALFORMED_ROOT_CA_DIGESTS_ENTRY = CFM_ERROR (0x17),		/**< CFM Root CA Digests entry too short. */
	CFM_MALFORMED_ALLOWABLE_PFM_ENTRY = CFM_ERROR (0x18),		/**< CFM Allowable PFM entry too short. */
	CFM_INVALID_TRANSCRIPT_HASH_TYPE = CFM_ERROR (0x19),		/**< CFM transcript hash type is invalid. */
	CFM_INVALID_MEASUREMENT_HASH_TYPE = CFM_ERROR (0x1A),		/**< CFM measurement hash type is invalid. */
};


#endif	/* CFM_H_ */
