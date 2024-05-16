// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PFM_MANAGER_H_
#define PFM_MANAGER_H_

#include <stddef.h>
#include <stdint.h>
#include "platform_api.h"
#include "common/observable.h"
#include "manifest/manifest_manager.h"
#include "manifest/pfm/pfm.h"
#include "manifest/pfm/pfm_observer.h"


/**
 * API for managing the PFM for a single set of protected flash.
 */
struct pfm_manager {
	struct manifest_manager base;	/**< Manifest manager interface */
	struct observable observable;	/**< The manager for PFM observers. */

	/**
	 * Get the active PFM for the protected flash.  The PFM instance must be released with the
	 * manager.
	 *
	 * @param manager The PFM manager to query.
	 *
	 * @return The active PFM or null if there is no active PFM.
	 */
	struct pfm* (*get_active_pfm) (const struct pfm_manager *manager);

	/**
	 * Get the PFM that is waiting to be activated.  The PFM instance must be released with the
	 * manager.
	 *
	 * @param manager The PFM manager to query.
	 *
	 * @return The pending PFM or null if there is no pending PFM.
	 */
	struct pfm* (*get_pending_pfm) (const struct pfm_manager *manager);

	/**
	 * Release a PFM instance retrieved from the manager.  PFM instances must only be released by
	 * the manager that allocated them.
	 *
	 * @param manager The PFM manager that allocated the PFM instance.
	 * @param pfm The PFM to release.
	 */
	void (*free_pfm) (const struct pfm_manager *manager, struct pfm *pfm);
};


int pfm_manager_add_observer (struct pfm_manager *manager, const struct pfm_observer *observer);
int pfm_manager_remove_observer (struct pfm_manager *manager, const struct pfm_observer *observer);

int pfm_manager_get_id_measured_data (struct pfm_manager *manager, size_t offset, uint8_t *buffer,
	size_t length, uint32_t *total_len);
int pfm_manager_hash_id_measured_data (struct pfm_manager *manager, struct hash_engine *hash);

int pfm_manager_get_platform_id_measured_data (struct pfm_manager *manager, size_t offset,
	uint8_t *buffer, size_t length, uint32_t *total_len);
int pfm_manager_hash_platform_id_measured_data (struct pfm_manager *manager,
	struct hash_engine *hash);

int pfm_manager_get_pfm_measured_data (struct pfm_manager *manager, size_t offset, uint8_t *buffer,
	size_t length, uint32_t *total_len);
int pfm_manager_hash_pfm_measured_data (struct pfm_manager *manager, struct hash_engine *hash);

/* Internal functions for use by derived types. */
int pfm_manager_init (struct pfm_manager *manager, struct hash_engine *hash, int port);
void pfm_manager_release (struct pfm_manager *manager);

void pfm_manager_on_pfm_verified (struct pfm_manager *manager);
void pfm_manager_on_pfm_activated (struct pfm_manager *manager);
void pfm_manager_on_clear_active (struct pfm_manager *manager);
void pfm_manager_on_pfm_activation_request (struct pfm_manager *manager);


#endif	/* PFM_MANAGER_H_ */
