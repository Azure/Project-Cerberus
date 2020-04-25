// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCD_OBSERVER_PCR_H_
#define PCD_OBSERVER_PCR_H_

#include "pcd_observer.h"
#include "pcd_manager.h"
#include "manifest/manifest_pcr.h"


/**
 * PCD observer to handle PCR updates when PCDs change.
 */
struct pcd_observer_pcr {
	struct pcd_observer base;		/**< The base observer interface. */
	struct manifest_pcr pcr;		/**< The PCR manager for the PCD. */
};


int pcd_observer_pcr_init (struct pcd_observer_pcr *observer, struct hash_engine *hash,
	struct pcr_store *store, uint16_t manifest_measurement, uint16_t manifest_id_measurement,
	uint16_t platform_id_measurement);
void pcd_observer_pcr_release (struct pcd_observer_pcr *observer);

void pcd_observer_pcr_record_measurement (struct pcd_observer_pcr *observer,
	struct pcd_manager *manager);


#endif /* PCD_OBSERVER_PCR_H_ */
