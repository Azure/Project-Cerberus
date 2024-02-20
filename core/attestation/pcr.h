// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCR_H_
#define PCR_H_

#include <stdint.h>
#include <stdbool.h>
#include "status/rot_status.h"
#include "crypto/hash.h"
#include "pcr_data.h"
#include "platform_api.h"
#include "platform_config.h"


/* Configurable PCR parameters.  Defaults can be overridden in platform_config.h. */
#ifndef PCR_MAX_DIGEST_LENGTH
#define PCR_MAX_DIGEST_LENGTH 								SHA512_HASH_LENGTH
#endif

#if PCR_MAX_DIGEST_LENGTH < SHA256_HASH_LENGTH
#error "Invalid maximum PCR digest length."
#endif


/* PCR flag to include data included in the measurement calculations */
#define PCR_MEASUREMENT_FLAG_EVENT							(1U << 0)
#define PCR_MEASUREMENT_FLAG_VERSION						(1U << 1)

/* TCG log definitions */
#define PCR_TCG_SHA256_ALG_ID								0x0B
#define PCR_TCG_SHA384_ALG_ID								0x0C
#define PCR_TCG_SHA512_ALG_ID								0x0D
#define PCR_TCG_SHA3_256_ALG_ID								0x27
#define PCR_TCG_SHA3_384_ALG_ID								0x28
#define PCR_TCG_SHA3_512_ALG_ID								0x29

#define PCR_TCG_EFI_NO_ACTION_EVENT_TYPE					0x03
#define PCR_TCG_SERVER_PLATFORM_CLASS						0x01
#define PCR_TCG_UINT_SIZE_32								0x01
#define PCR_TCG_LOG_SIGNATURE								"Spec ID Event03"

/**
 * DMTF measurement value type identifiers indicating what type of data is being reported. Defined
 * in the SPDM DSP0274 spec section 10.11.1.1.
 */
enum pcr_dmtf_value_type {
	PCR_DMTF_VALUE_TYPE_ROM = 0x00,				/**< Immutable ROM. */
	PCR_DMTF_VALUE_TYPE_FIRMWARE = 0x01,		/**< Mutable firmware. */
	PCR_DMTF_VALUE_TYPE_HW_CONFIG = 0x02,		/**< Hardware configuration, such as straps. */
	PCR_DMTF_VALUE_TYPE_FW_CONFIG = 0x03,		/**< Firmware configuration, such as configurable firmware policy. */
	PCR_DMTF_VALUE_TYPE_MEAS_MANIFEST = 0x04,	/**< Measurement manifest. */

	/**
	 * Other values are defined in SPDM specs 1.2 and 1.3, but are not used here to allow for easier
	 * compatibility with SPDM 1.1.
	 */
	PCR_DMTF_VALUE_TYPE_UNUSED = 0x05,

	PCR_DMTF_VALUE_TYPE_RESERVED = 0x0b,		/**< Reserved. */
};


/**
 * Configuration details for a set of measurements in a PCR.
 */
struct pcr_config {
	uint8_t num_measurements;			/**< The number of measurements in the PCR. */
	enum hash_type measurement_algo;	/**< Hash algorithm used for measurements in the PCR. */
};

/**
 * Descriptor for a single measurement contained in a PCR.
 */
struct pcr_measurement {
	uint8_t digest[PCR_MAX_DIGEST_LENGTH];			/**< Digest of the data for the measurement. */
	uint8_t measurement[PCR_MAX_DIGEST_LENGTH];		/**< Extended value using the measurement digest. */
	const struct pcr_measured_data *measured_data;	/**< Accessor for the raw data that was measured. */
	uint32_t event_type;							/**< TCG event type identifier. */
	uint8_t version;								/**< Version associated with the measurement data. */
	uint8_t measurement_config;						/**< Indicates additional data to include in measurement digests. */
	enum pcr_dmtf_value_type dmtf_type;				/**< DMTF value type identifier. */
	bool spdm_not_tcb;								/**< Flag to skip the measurement from SPDM TCB reports. */
};

/**
 * Descriptor for a single PCR managed by the device, which contains a list of individual
 * measurements.
 */
struct pcr_bank {
	struct pcr_measurement *measurement_list;	/**< List of measurements in the PCR. */
	struct pcr_config config;					/**< Configuration for the PCR and measurements. */
	bool explicit_measurement;					/**< Flag to indicate that the PCR is an explicit measurement. */
	platform_mutex lock;						/**< Synchronization lock. */
};

#pragma pack(push, 1)
/**
 * Header for the TCG_PCR_EVENT2 log structure.
 */
struct pcr_tcg_event2_header {
	uint32_t pcr_index;						/**< Index for the PCR containing the measurement. */
	uint32_t event_type;					/**< Event identifier for the measurement. */
	uint32_t digest_count;					/**< Number of digests calculated for the event. */
	uint16_t digest_algorithm_id;			/**< ID of hashing algorithm used to calculate the digest. */
};

/**
 * TCG event entry with a single SHA-256 digest.
 */
struct pcr_tcg_event2_sha256 {
	struct pcr_tcg_event2_header header;	/**< Event entry header. */
	uint8_t digest[SHA256_HASH_LENGTH];		/**< SHA-256 digest that was extended to PCR. */
	uint32_t event_size;					/**< Length of the data that was measured. */
};

/**
 * TCG event entry with a single SHA-384 digest.
 */
struct pcr_tcg_event2_sha384 {
	struct pcr_tcg_event2_header header;	/**< Event entry header. */
	uint8_t digest[SHA384_HASH_LENGTH];		/**< SHA-384 digest that was extended to PCR. */
	uint32_t event_size;					/**< Length of the data that was measured. */
};

/**
 * TCG event entry with a single SHA-512 digest.
 */
struct pcr_tcg_event2_sha512 {
	struct pcr_tcg_event2_header header;	/**< Event entry header. */
	uint8_t digest[SHA512_HASH_LENGTH];		/**< SHA-512 digest that was extended to PCR. */
	uint32_t event_size;					/**< Length of the data that was measured. */
};

/**
 * TCG event entry using the TCG_PCR_EVENT log structure.
 */
struct pcr_tcg_event {
	uint32_t pcr_index;					/**< Index for the PCR containing the measurement. */
	uint32_t event_type;				/**< Event identifier for the measurement. */
	uint8_t digest[SHA1_HASH_LENGTH];	/**< SHA-1 digest for the event. */
	uint32_t event_size;				/**< Length of the data that was measured. */
	//uint8_t event[0];					/**< Event data. Commented out since not used by Cerberus. */
};

/**
 * TCG event log algorithm descriptor.
 */
struct pcr_tcg_algorithm {
	uint16_t digest_algorithm_id;	/**< Identifier for a hashing algorithm used in the log. */
	uint16_t digest_size;			/**< Length of the digest that is generated by the specified algorithm. */
};

/**
 * TCG event log header.
 */
struct pcr_tcg_log_header {
	uint8_t signature[16];						/**< The null terminated ASCII string "Spec ID Event03" */
	uint32_t platform_class;					/**< Platform class as defined in TCG spec */
	uint8_t spec_version_minor;					/**< Spec minor version number */
	uint8_t spec_version_major;					/**< Spec major version number */
	uint8_t spec_errata;						/**< Spec errata supported */
	uint8_t uintn_size;							/**< Size of uint fields */
	uint32_t num_algorithms;					/**< Number of hashing algorithms used in log */
	struct pcr_tcg_algorithm digest_size[3];	/**< List of hashing algorithm descriptors */
	uint8_t vendor_info_size;					/**< Size of vendorInfo */
	//uint8_t vendor_info[0];					/**< Vendor-specific extra information. Commented out since not used by Cerberus */
};
#pragma pack(pop)


int pcr_init (struct pcr_bank *pcr, const struct pcr_config *config);
void pcr_release (struct pcr_bank *pcr);

int pcr_get_num_measurements (struct pcr_bank *pcr);
int pcr_check_measurement_index (struct pcr_bank *pcr, uint8_t measurement_index);

enum hash_type pcr_get_hash_algorithm (struct pcr_bank *pcr);
int pcr_get_digest_length (struct pcr_bank *pcr);

int pcr_set_tcg_event_type (struct pcr_bank *pcr, uint8_t measurement_index, uint32_t event_type);
int pcr_get_tcg_event_type (struct pcr_bank *pcr, uint8_t measurement_index, uint32_t *event_type);

int pcr_set_dmtf_value_type (struct pcr_bank *pcr, uint8_t measurement_index,
	enum pcr_dmtf_value_type value_type, bool is_not_tcb);
int pcr_get_dmtf_value_type (struct pcr_bank *pcr, uint8_t measurement_index,
	enum pcr_dmtf_value_type *value_type);
int pcr_is_measurement_in_tcb (struct pcr_bank *pcr, uint8_t measurement_index);

int pcr_update_digest (struct pcr_bank *pcr, uint8_t measurement_index, const uint8_t *digest,
	size_t digest_len);
int pcr_update_buffer (struct pcr_bank *pcr, struct hash_engine *hash, uint8_t measurement_index,
	const uint8_t *buf, size_t buf_len, bool include_event);
int pcr_update_versioned_buffer (struct pcr_bank *pcr, struct hash_engine *hash,
	uint8_t measurement_index, const uint8_t *buf, size_t buf_len, bool include_event,
	uint8_t version);
int pcr_invalidate_measurement (struct pcr_bank *pcr, uint8_t measurement_index);

int pcr_compute (struct pcr_bank *pcr, struct hash_engine *hash, bool lock, uint8_t *measurement,
	size_t length);
int pcr_get_measurement (struct pcr_bank *pcr, uint8_t measurement_index,
	struct pcr_measurement *measurement);
int pcr_get_all_measurements (struct pcr_bank *pcr,
	const struct pcr_measurement **measurement_list);

int pcr_is_measurement_data_available (struct pcr_bank *pcr, uint8_t measurement_index);
int pcr_set_measurement_data (struct pcr_bank *pcr, uint8_t measurement_index,
	const struct pcr_measured_data *measurement_data);
int pcr_get_measurement_data (struct pcr_bank *pcr, uint8_t measurement_index, size_t offset,
	uint8_t *buffer, size_t length, size_t *total_len);
int pcr_hash_measurement_data (struct pcr_bank *pcr, uint8_t measurement_index,
	struct hash_engine *hash, enum hash_type hash_type, uint8_t *buffer, size_t length);

int pcr_get_tcg_log (struct pcr_bank *pcr, uint32_t pcr_num, size_t offset, uint8_t *buffer,
	size_t length, size_t *total_len);

int pcr_lock (struct pcr_bank *pcr);
int pcr_unlock (struct pcr_bank *pcr);


#define	PCR_ERROR(code)		ROT_ERROR (ROT_MODULE_PCR, code)

/**
 * Error codes that can be generated by the PCR management module.
 */
enum {
	PCR_INVALID_ARGUMENT = PCR_ERROR (0x00),					/**< Input parameter is null or not valid. */
	PCR_NO_MEMORY = PCR_ERROR (0x01),							/**< Memory allocation failed. */
	PCR_UNSUPPORTED_ALGO = PCR_ERROR (0x02),					/**< Unsupported hashing algorithm. */
	PCR_INVALID_PCR = PCR_ERROR (0x03),							/**< Invalid PCR bank. */
	PCR_INVALID_TYPE = PCR_ERROR (0x04),						/**< Invalid measurement type. */
	PCR_INVALID_INDEX = PCR_ERROR (0x05),						/**< Invalid measurement index. */
	PCR_INVALID_DATA_TYPE = PCR_ERROR (0x06),					/**< Invalid PCR measured data type. */
	PCR_MEASURED_DATA_INVALID_MEMORY = PCR_ERROR (0x08),		/**< PCR Measured data memory location is null or invalid */
	PCR_MEASURED_DATA_INVALID_FLASH_DEVICE = PCR_ERROR (0x09),	/**< Flash device storing PCR Measured data is null or invalid */
	PCR_MEASURED_DATA_INVALID_CALLBACK = PCR_ERROR (0x0a),		/**< Callback to retrieve PCR Measured data is null or invalid */
	PCR_INCORRECT_DIGEST_LENGTH = PCR_ERROR (0x0b),				/**< The digest length is not correct for the PCR. */
	PCR_SMALL_OUTPUT_BUFFER = PCR_ERROR (0x0c),					/**< The output buffer is not large enough for the PCR. */
	PCR_INVALID_VALUE_TYPE = PCR_ERROR (0x0d),					/**< Invalid DMTF value type identifier. */
	PCR_INVALID_SEQUENTIAL_ID = PCR_ERROR (0x0e),				/**< Invalid sequential measurement ID. */
	PCR_MEASURED_DATA_NOT_AVIALABLE = PCR_ERROR (0x0f),			/**< The raw measured data is not available for the measurement. */
	PCR_MEASURED_DATA_NO_HASH_CALLBACK = PCR_ERROR (0x10),		/**< The measured data does not provide a hash callback. */
};


#endif /* PCR_H_ */
