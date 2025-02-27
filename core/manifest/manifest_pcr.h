// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_PCR_H_
#define MANIFEST_PCR_H_

#include <stdint.h>
#include "manifest.h"
#include "attestation/pcr_store.h"
#include "crypto/hash.h"


/**
 * PCR management for a single manifest.  This is not a stand-alone module, and should only be used
 * as part of a parent module.
 */
struct manifest_pcr {
	const struct hash_engine *hash;				/**< The hash engine for generating measurements. */
	struct pcr_store *store;					/**< Storage for PCR measurements. */
	uint16_t manifest_measurement;				/**< The identifier for the manifest measurement. */
	uint16_t manifest_id_measurement;			/**< The identifier for manifest ID measurement. */
	uint16_t manifest_platform_id_measurement;	/**< The identifier for manifest platform ID measurement. */
};


int manifest_pcr_init (struct manifest_pcr *pcr, const struct hash_engine *hash,
	struct pcr_store *store, uint16_t manifest_measurement, uint16_t manifest_id_measurement,
	uint16_t manifest_platform_id_measurement, int error);
void manifest_pcr_release (const struct manifest_pcr *pcr);

int manifest_pcr_check_measurements (const struct manifest_pcr *pcr, int invalid_arg,
	int not_unique);

int manifest_pcr_record_manifest_measurement (const struct manifest_pcr *pcr,
	const struct manifest *active);

int manifest_pcr_measure_manifest (const struct manifest *active, const struct hash_engine *hash,
	struct pcr_store *store, uint16_t manifest_measurement, uint16_t manifest_id_measurement,
	uint16_t manifest_platform_id_measurement);


#endif	/* MANIFEST_PCR_H_ */
