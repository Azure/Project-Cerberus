// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PFM_OBSERVER_PCR_H_
#define PFM_OBSERVER_PCR_H_

#include "pfm_observer.h"
#include "pfm_manager.h"
#include "manifest/manifest_pcr.h"


/**
 * PFM observer to handle PCR updates when PFMs change.
 */
struct pfm_observer_pcr {
	struct pfm_observer base;				/**< The base observer interface. */
	struct manifest_pcr pcr;				/**< The PCR manager for the PFM. */
};


int pfm_observer_pcr_init (struct pfm_observer_pcr *observer, struct hash_engine *hash,
	struct pcr_store *store, uint16_t manifest_measurement, uint16_t manifest_id_measurement,
	uint16_t platform_id_measurement);
void pfm_observer_pcr_release (struct pfm_observer_pcr *observer);

void pfm_observer_pcr_record_measurement (struct pfm_observer_pcr *observer,
	struct pfm_manager *manager);


#endif /* PFM_OBSERVER_PCR_H_ */
