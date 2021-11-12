// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCR_STORE_H_
#define PCR_STORE_H_

#include <stdint.h>
#include "crypto/hash.h"
#include "logging/logging.h"
#include "pcr.h"
#include "pcr_data.h"


#define	PCR_MEASUREMENT(bank, index)					((bank) << 8 | (index))


/**
 * Container for PCR banks
 */
struct pcr_store {
	struct pcr_bank *banks;								/**< PCR banks */
	size_t num_pcr_banks;								/**< Number of PCR banks */
};

#pragma pack(push, 1)

/**
 * Format for an entry in the attestation log.
 */
struct pcr_store_attestation_log_entry_info {
	uint32_t event_type;								/**< TCG event type */
	uint32_t measurement_type;							/**< PCR and measurement index */
	uint32_t digest_count;								/**< Number of digests. */
	uint16_t digest_algorithm_id;						/**< ID of hashing algorithm. */
	uint8_t digest[SHA256_HASH_LENGTH];					/**< Value extended to measurement. */
	uint32_t measurement_size;							/**< Measurement size. */
	uint8_t measurement[SHA256_HASH_LENGTH];			/**< Resultant measurement. */
};


/**
 * Logging attestation entry structure
 */
struct pcr_store_attestation_log_entry {
	struct logging_entry_header header;					/**< Standard logging header. */
	struct pcr_store_attestation_log_entry_info entry;	/**< Information for the log entry. */
};

#pragma pack(pop)


int pcr_store_init (struct pcr_store *store, uint8_t *num_pcr_measurements, size_t num_pcr);
void pcr_store_release (struct pcr_store *store);

int pcr_store_check_measurement_type (struct pcr_store *store, uint16_t measurement_type);
int pcr_store_get_num_banks (struct pcr_store *store);

int pcr_store_update_digest (struct pcr_store *store, uint16_t measurement_type,
	const uint8_t *digest, size_t digest_len);
int pcr_store_update_buffer (struct pcr_store *store, struct hash_engine *hash,
	uint16_t measurement_type, const uint8_t *buf, size_t buf_len, bool include_event);
int pcr_store_update_versioned_buffer (struct pcr_store *store, struct hash_engine *hash,
	uint16_t measurement_type, const uint8_t *buf, size_t buf_len, bool include_event,
	uint8_t version);
int pcr_store_update_event_type (struct pcr_store *store, uint16_t measurement_type,
	uint32_t event_type);

int pcr_store_compute (struct pcr_store *store, struct hash_engine *hash, uint8_t pcr_num,
	uint8_t *measurement);
int pcr_store_get_measurement (struct pcr_store *store, uint16_t measurement_type,
	struct pcr_measurement *measurement);
int pcr_store_invalidate_measurement (struct pcr_store *store, uint16_t measurement_type);

int pcr_store_get_attestation_log (struct pcr_store *store, struct hash_engine *hash,
	uint32_t offset, uint8_t *contents, size_t length);
int pcr_store_get_attestation_log_size (struct pcr_store *store);

int pcr_store_get_tcg_log (struct pcr_store *store, uint8_t *buffer, size_t offset, size_t length);

int pcr_store_set_measurement_data (struct pcr_store *store, uint16_t measurement_type,
	struct pcr_measured_data *measurement);
int pcr_store_get_measurement_data (struct pcr_store *store, uint16_t measurement_type,
	size_t offset, uint8_t *buffer, size_t length);


#endif //PCR_STORE_H_
