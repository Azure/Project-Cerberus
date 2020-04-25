// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CFM_OBSERVER_PCR_H_
#define CFM_OBSERVER_PCR_H_

#include "cfm_observer.h"
#include "cfm_manager.h"
#include "manifest/manifest_pcr.h"


/**
 * CFM observer to handle PCR updates when CFMs change.
 */
struct cfm_observer_pcr {
	struct cfm_observer base;				/**< The base observer interface. */
	struct manifest_pcr pcr;				/**< The PCR manager for the CFM. */
};


int cfm_observer_pcr_init (struct cfm_observer_pcr *observer, struct hash_engine *hash,
	struct pcr_store *store, uint16_t manifest_measurement, uint16_t manifest_id_measurement,
	uint16_t platform_id_measurement);
void cfm_observer_pcr_release (struct cfm_observer_pcr *observer);

void cfm_observer_pcr_record_measurement (struct cfm_observer_pcr *observer,
	struct cfm_manager *manager);


#endif /* CFM_OBSERVER_PCR_H_ */
