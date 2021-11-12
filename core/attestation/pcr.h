// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCR_H_
#define PCR_H_

#include <stdint.h>
#include <stdbool.h>
#include "status/rot_status.h"
#include "platform.h"
#include "crypto/hash.h"
#include "pcr_data.h"


#define PCR_DIGEST_LENGTH 									SHA256_HASH_LENGTH

/* PCR flag to include data in measurement calculations */
#define PCR_MEASUREMENT_FLAG_EVENT							(1U << 0)
#define PCR_MEASUREMENT_FLAG_VERSION						(1U << 1)

/* TCG log definitions */
#define PCR_TCG_SHA256_ALG_ID								0x0B
#define PCR_TCG_EFI_NO_ACTION_EVENT_TYPE					0x03
#define PCR_TCG_SERVER_PLATFORM_CLASS						0x01
#define PCR_TCG_UINT_SIZE_32								0x01
#define PCR_TCG_LOG_SIGNATURE				 				"Spec ID Event03"

/**
 * Container for a PCR measurement
 */
struct pcr_measurement {
	uint8_t digest[PCR_DIGEST_LENGTH];						/**< Digest buffer */
	uint8_t measurement[PCR_DIGEST_LENGTH];					/**< Aggregated measurement buffer */
	struct pcr_measured_data *measured_data;				/**< Raw data used for measurement */
	uint32_t event_type;									/**< TCG event type */
	uint8_t version;										/**< Version associated with the measurement data */
	uint8_t measurement_config;								/**< Indicates data to include in measurement calculations */
};

/**
 * List of measurements to be aggregated in a PCR
 */
struct pcr_bank {
	struct pcr_measurement *measurement_list;				/**< List of measurements */
	size_t num_measurements;								/**< Number of measurements */
	bool explicit_measurement;								/**< PCR bank contains an explicit measurement */
	platform_mutex lock;									/**< Synchronization lock */
};

#pragma pack(push, 1)
/**
 * TCG event entry.
 */
struct pcr_tcg_event2 {
	uint32_t pcr_bank;										/**< PCR bank */
	uint32_t event_type;									/**< Type of event */
	uint32_t digest_count;									/**< Number of digests */
	uint16_t digest_algorithm_id;							/**< ID of hashing algorithm */
	uint8_t digest[32];										/**< Digest extended to PCR */
	uint32_t event_size;									/**< Event size */
};

/**
 * TCG event entry - old format.
 */
struct pcr_tcg_event {
	uint32_t pcr_bank;										/**< PCR bank */
	uint32_t event_type;									/**< Type of event */
	uint8_t pcr[20];										/**< PCR value */
	uint32_t event_size;									/**< Event size */
	//uint8_t event[0];										/**< Event. Commented out since not used by Cerberus */
};

/**
 * TCG event log algorithm descriptor.
 */
struct pcr_tcg_algorithm {
	uint16_t digest_algorithm_id;							/**< Algorithm ID */
	uint16_t digest_size;									/**< Algorithm digest size */
};

/**
 * TCG event log header.
 */
struct pcr_tcg_log_header {
	uint8_t signature[16];									/**< The null terminated ASCII string "Spec ID Event03" */
	uint32_t platform_class;								/**< Platform class as defined in TCG spec */
	uint8_t spec_version_minor;								/**< Spec minor version number */
	uint8_t spec_version_major;								/**< Spec major version number */
	uint8_t spec_errata;									/**< Spec errata supported */
	uint8_t uintn_size;										/**< Size of uint fields */
	uint32_t num_algorithms;								/**< Number of hashing algorithms used in log */
	struct pcr_tcg_algorithm digest_size;					/**< Hashing algorithms descriptors */
	uint8_t vendor_info_size;								/**< Size of vendorInfo */
	//uint8_t vendor_info[0];								/**< Vendor-specific extra information. Commented out since not used by Cerberus */
};
#pragma pack(pop)


int pcr_init (struct pcr_bank *pcr, uint8_t pcr_num_measurements);
void pcr_release (struct pcr_bank *pcr);

int pcr_check_measurement_index (struct pcr_bank *pcr, uint8_t measurement_index);

int pcr_update_digest (struct pcr_bank *pcr, uint8_t measurement_index, const uint8_t *digest,
	size_t digest_len);
int pcr_update_buffer (struct pcr_bank *pcr, struct hash_engine *hash, uint8_t measurement_index,
	const uint8_t *buf, size_t buf_len, bool include_event);
int pcr_update_versioned_buffer (struct pcr_bank *pcr, struct hash_engine *hash,
	uint8_t measurement_index, const uint8_t *buf, size_t buf_len, bool include_event,
	uint8_t version);

int pcr_update_event_type (struct pcr_bank *pcr, uint8_t measurement_index, uint32_t event_type);
int pcr_get_event_type (struct pcr_bank *pcr, uint8_t measurement_index, uint32_t *event_type);

int pcr_compute (struct pcr_bank *pcr, struct hash_engine *hash, uint8_t *measurement, bool lock);
int pcr_get_measurement (struct pcr_bank *pcr, uint8_t measurement_index,
	struct pcr_measurement *measurement);
int pcr_get_all_measurements (struct pcr_bank *pcr, const uint8_t **measurement_list);
int pcr_get_num_measurements (struct pcr_bank *pcr);
int pcr_invalidate_measurement_index (struct pcr_bank *pcr, uint8_t measurement_index);

int pcr_set_measurement_data (struct pcr_bank *pcr, uint8_t measurement_index,
	struct pcr_measured_data *measurement_data);
int pcr_get_measurement_data (struct pcr_bank *pcr, uint8_t measurement_index, size_t offset,
	uint8_t *buffer, size_t length, uint32_t *total_len);

int pcr_get_tcg_log (struct pcr_bank *pcr, uint32_t pcr_num, uint8_t *buffer, size_t offset,
	size_t length, size_t *total_len);

int pcr_lock (struct pcr_bank *pcr);
int pcr_unlock (struct pcr_bank *pcr);


#define	PCR_ERROR(code)		ROT_ERROR (ROT_MODULE_PCR, code)

/**
 * Error codes that can be generated by the PCR management module.
 */
enum {
	PCR_INVALID_ARGUMENT = PCR_ERROR (0x00),						/**< Input parameter is null or not valid. */
	PCR_NO_MEMORY = PCR_ERROR (0x01),								/**< Memory allocation failed. */
	PCR_UNSUPPORTED_ALGO = PCR_ERROR (0x02),						/**< Unsupported hashing algorithm. */
	PCR_INVALID_PCR = PCR_ERROR (0x03),								/**< Invalid PCR bank. */
	PCR_INVALID_TYPE = PCR_ERROR (0x04),							/**< Invalid measurement type. */
	PCR_INVALID_INDEX = PCR_ERROR (0x05),							/**< Invalid measurement index. */
	PCR_INVALID_DATA_TYPE = PCR_ERROR (0x06),						/**< Invalid PCR measured data type. */
	PCR_MEASURED_DATA_INVALID_MEMORY = PCR_ERROR (0x08),			/**< PCR Measured data memory location is null or invalid */
	PCR_MEASURED_DATA_INVALID_FLASH_DEVICE = PCR_ERROR (0x09),		/**< Flash device storing PCR Measured data is null or invalid */
	PCR_MEASURED_DATA_INVALID_CALLBACK = PCR_ERROR (0x0A),			/**< Callback to retrieve PCR Measured data is null or invalid */
};


#endif //PCR_H_
