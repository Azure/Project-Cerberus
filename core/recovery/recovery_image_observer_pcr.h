// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RECOVERY_IMAGE_OBSERVER_PCR_H_
#define RECOVERY_IMAGE_OBSERVER_PCR_H_

#include "recovery_image_observer.h"
#include "recovery_image_manager.h"


/**
 * Recovery image observer to handle PCR updates when the recovery image changes.
 */
struct recovery_image_observer_pcr {
	struct recovery_image_observer base;		/**< The base observer interface. */
	struct hash_engine *hash;					/**< The hash engine for generating measurements. */
	struct pcr_store *store;					/**< Storage for PCR measurements. */
	uint16_t measurement_id;					/**< The type identifier for the measurement. */
};


int recovery_image_observer_pcr_init (struct recovery_image_observer_pcr *observer, struct hash_engine *hash,
	struct pcr_store *store, uint16_t measurement_type);
void recovery_image_observer_pcr_release (struct recovery_image_observer_pcr *observer);

void recovery_image_observer_pcr_record_measurement (struct recovery_image_observer_pcr *observer,
	struct recovery_image_manager *manager);


#endif /* RECOVERY_IMAGE_OBSERVER_PCR_H_ */
