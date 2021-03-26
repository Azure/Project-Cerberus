// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCD_MANAGER_H_
#define PCD_MANAGER_H_

#include <stdint.h>
#include <stddef.h>
#include "manifest/manifest_manager.h"
#include "manifest/pcd/pcd.h"
#include "manifest/pcd/pcd_observer.h"
#include "common/observable.h"


/**
 * API for managing a PCD.
 */
struct pcd_manager {
	struct manifest_manager base;					/**< Manifest manager interface */
	struct observable observable;					/**< The manager for PCD observers. */

	/**
	 * Get the active PCD. The PCD instance must be released with the manager.
	 *
	 * @param manager The PCD manager to query.
	 *
	 * @return The active PCD or null if there is no active PCD.
	 */
	struct pcd* (*get_active_pcd) (struct pcd_manager *manager);

	/**
	 * Release a PCD instance retrieved from the manager. PCD instances must only be released by
	 * the manager that allocated them.
	 *
	 * @param manager The PCD manager that allocated the PCD instance.
	 * @param pcd The PCD to release.
	 */
	void (*free_pcd) (struct pcd_manager *manager, struct pcd *pcd);
};


int pcd_manager_add_observer (struct pcd_manager *manager, struct pcd_observer *observer);
int pcd_manager_remove_observer (struct pcd_manager *manager, struct pcd_observer *observer);

/* Internal functions for use by derived types. */
int pcd_manager_init (struct pcd_manager *manager, struct hash_engine *hash);
void pcd_manager_release (struct pcd_manager *manager);

void pcd_manager_on_pcd_verified (struct pcd_manager *manager, struct pcd *pending);
void pcd_manager_on_pcd_activated (struct pcd_manager *manager);
void pcd_manager_on_clear_active (struct pcd_manager *manager);

int pcd_manager_get_id_measured_data (struct pcd_manager *manager, size_t offset, uint8_t *buffer,
	size_t length, uint32_t *total_len);
int pcd_manager_get_platform_id_measured_data (struct pcd_manager *manager, size_t offset,
	uint8_t *buffer, size_t length, uint32_t *total_len);
int pcd_manager_get_pcd_measured_data (struct pcd_manager *manager, size_t offset, uint8_t *buffer,
	size_t length, uint32_t *total_len);


#endif /* PCD_MANAGER_H_ */
