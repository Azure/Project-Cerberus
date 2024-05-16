// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCR_STORE_H_
#define PCR_STORE_H_

#include <stdint.h>
#include "pcr.h"
#include "pcr_data.h"
#include "crypto/hash.h"
#include "logging/logging.h"


/**
 * Identifier for a specific measurement in the PCR store.
 *
 * @param pcr The PCR number containing the measurement.
 * @param measurement The specific measurement index in the PCR.
 */
#define	PCR_MEASUREMENT(pcr, measurement)				(((pcr) << 8) | (measurement))


/**
 * Storage for all PCRs maintained by the device.
 */
struct pcr_store {
	struct pcr_bank *pcrs;	/**< List of individual PCRs for the device.*/
	uint8_t num_pcrs;		/**< The number of PCRs in the list. */
};

#pragma pack(push, 1)

/**
 * Format for an entry in the attestation log.
 */
struct pcr_store_attestation_log_entry_info {
	uint32_t event_type;			/**< TCG event type for the measurement. */
	uint32_t measurement_type;		/**< PCR and measurement index. */
	uint32_t digest_count;			/**< Number of digests in the log entry. */
	uint16_t digest_algorithm_id;	/**< TCG ID of the hashing algorithm used. */
};

/**
 * Container for SHA-256 measurement digests.
 */
struct pcr_store_attestation_log_digest_sha256 {
	uint8_t digest[SHA256_HASH_LENGTH];			/**< Digest extended to the PCR for the measurement. */
	uint32_t measurement_size;					/**< Length of the measurement. */
	uint8_t measurement[SHA256_HASH_LENGTH];	/**< Extended PCR value for this measurement. */
};

/**
 * Container for SHA-384 measurement digests.
 */
struct pcr_store_attestation_log_digest_sha384 {
	uint8_t digest[SHA384_HASH_LENGTH];			/**< Digest extended to the PCR for the measurement. */
	uint32_t measurement_size;					/**< Length of the measurement. */
	uint8_t measurement[SHA384_HASH_LENGTH];	/**< Extended PCR value for this measurement. */
};

/**
 * Container for SHA-512 measurement digests.
 */
struct pcr_store_attestation_log_digest_sha512 {
	uint8_t digest[SHA512_HASH_LENGTH];			/**< Digest extended to the PCR for the measurement. */
	uint32_t measurement_size;					/**< Length of the measurement. */
	uint8_t measurement[SHA512_HASH_LENGTH];	/**< Extended PCR value for this measurement. */
};

/**
 * Logging attestation entry structure without the variable length measurements.
 */
struct pcr_store_attestation_log_entry_base {
	struct logging_entry_header header;					/**< Standard logging header. */
	struct pcr_store_attestation_log_entry_info info;	/**< Information for the log entry. */
};

/**
 * Logging attestation entry structure containing a SHA-256 measurement.
 */
struct pcr_store_attestation_log_entry_sha256 {
	struct pcr_store_attestation_log_entry_base base;		/**< Algorithm agnostic entry information. */
	struct pcr_store_attestation_log_digest_sha256 entry;	/**< Measurement details for the log entry. */
};

/**
 * Logging attestation entry structure containing a SHA-384 measurement.
 */
struct pcr_store_attestation_log_entry_sha384 {
	struct pcr_store_attestation_log_entry_base base;		/**< Algorithm agnostic entry information. */
	struct pcr_store_attestation_log_digest_sha384 entry;	/**< Measurement details for the log entry. */
};

/**
 * Logging attestation entry structure containing a SHA-512 measurement.
 */
struct pcr_store_attestation_log_entry_sha512 {
	struct pcr_store_attestation_log_entry_base base;		/**< Algorithm agnostic entry information. */
	struct pcr_store_attestation_log_digest_sha512 entry;	/**< Measurement details for the log entry. */
};

#pragma pack(pop)


int pcr_store_init (struct pcr_store *store, const struct pcr_config *pcr_config, uint8_t num_pcrs);
void pcr_store_release (struct pcr_store *store);

int pcr_store_check_measurement_type (struct pcr_store *store, uint16_t measurement_type);
int pcr_store_get_measurement_type (struct pcr_store *store, size_t sequential_id);

int pcr_store_get_num_pcrs (struct pcr_store *store);
int pcr_store_get_num_total_measurements (struct pcr_store *store);
int pcr_store_get_num_pcr_measurements (struct pcr_store *store, uint8_t pcr_num);
int pcr_store_get_pcr_digest_length (struct pcr_store *store, uint8_t pcr_num);

int pcr_store_set_tcg_event_type (struct pcr_store *store, uint16_t measurement_type,
	uint32_t event_type);

int pcr_store_set_dmtf_value_type (struct pcr_store *store, uint16_t measurement_type,
	enum pcr_dmtf_value_type value_type, bool is_not_tcb);
int pcr_store_get_dmtf_value_type (struct pcr_store *store, uint16_t measurement_type,
	enum pcr_dmtf_value_type *value_type);
int pcr_store_is_measurement_in_tcb (struct pcr_store *store, uint16_t measurement_type);

int pcr_store_update_digest (struct pcr_store *store, uint16_t measurement_type,
	const uint8_t *digest, size_t digest_len);
int pcr_store_update_buffer (struct pcr_store *store, struct hash_engine *hash,
	uint16_t measurement_type, const uint8_t *buf, size_t buf_len, bool include_event);
int pcr_store_update_versioned_buffer (struct pcr_store *store, struct hash_engine *hash,
	uint16_t measurement_type, const uint8_t *buf, size_t buf_len, bool include_event,
	uint8_t version);

int pcr_store_const_update_digest (struct pcr_store *store, uint16_t measurement_type,
	const uint8_t *digest, size_t digest_len);
int pcr_store_const_update_buffer (struct pcr_store *store, struct hash_engine *hash,
	uint16_t measurement_type, const uint8_t *buf, size_t buf_len, bool include_event);
int pcr_store_const_update_versioned_buffer (struct pcr_store *store, struct hash_engine *hash,
	uint16_t measurement_type, const uint8_t *buf, size_t buf_len, bool include_event,
	uint8_t version);

int pcr_store_invalidate_measurement (struct pcr_store *store, uint16_t measurement_type);

int pcr_store_compute_pcr (struct pcr_store *store, struct hash_engine *hash, uint8_t pcr_num,
	uint8_t *measurement, size_t length);
int pcr_store_get_measurement (struct pcr_store *store, uint16_t measurement_type,
	struct pcr_measurement *measurement);

int pcr_store_set_measurement_data (struct pcr_store *store, uint16_t measurement_type,
	const struct pcr_measured_data *measurement);
int pcr_store_get_measurement_data (struct pcr_store *store, uint16_t measurement_type,
	size_t offset, uint8_t *buffer, size_t length);
int pcr_store_hash_measurement_data (struct pcr_store *store, uint16_t measurement_type,
	struct hash_engine *hash, enum hash_type hash_type, uint8_t *buffer, size_t length);

int pcr_store_is_measurement_data_available (struct pcr_store *store, uint16_t measurement_type);
int pcr_store_get_measurement_data_length (struct pcr_store *store, uint16_t measurement_type);

int pcr_store_get_attestation_log_size (struct pcr_store *store);
int pcr_store_get_attestation_log (struct pcr_store *store, struct hash_engine *hash, size_t offset,
	uint8_t *contents, size_t length);

int pcr_store_get_tcg_log (struct pcr_store *store, size_t offset, uint8_t *buffer, size_t length);


#endif	/* PCR_STORE_H_ */
