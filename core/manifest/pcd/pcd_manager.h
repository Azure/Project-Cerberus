// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCD_MANAGER_H_
#define PCD_MANAGER_H_

#include <stddef.h>
#include <stdint.h>
#include "common/observable.h"
#include "manifest/manifest_manager.h"
#include "manifest/pcd/pcd.h"
#include "manifest/pcd/pcd_observer.h"


/**
 * Variable context for managing a single PCD.
 */
struct pcd_manager_state {
	struct observable observable;	/**< The manager for PCD observers. */
};

/**
 * API for managing a PCD.
 */
struct pcd_manager {
	struct manifest_manager base;	/**< Manifest manager interface */

	/**
	 * Get the active PCD. The PCD instance must be released with the manager.
	 *
	 * @param manager The PCD manager to query.
	 *
	 * @return The active PCD or null if there is no active PCD.
	 */
	const struct pcd* (*get_active_pcd) (const struct pcd_manager *manager);

	/**
	 * Release a PCD instance retrieved from the manager. PCD instances must only be released by
	 * the manager that allocated them.
	 *
	 * @param manager The PCD manager that allocated the PCD instance.
	 * @param pcd The PCD to release.
	 */
	void (*free_pcd) (const struct pcd_manager *manager, const struct pcd *pcd);

	struct pcd_manager_state *state;	/**< Variable context for PCD management. */
};


int pcd_manager_add_observer (const struct pcd_manager *manager,
	const struct pcd_observer *observer);
int pcd_manager_remove_observer (const struct pcd_manager *manager,
	const struct pcd_observer *observer);

int pcd_manager_get_id_measured_data (const struct pcd_manager *manager, size_t offset,
	uint8_t *buffer, size_t length, uint32_t *total_len);
int pcd_manager_hash_id_measured_data (const struct pcd_manager *manager,
	const struct hash_engine *hash);

int pcd_manager_get_platform_id_measured_data (const struct pcd_manager *manager, size_t offset,
	uint8_t *buffer, size_t length, uint32_t *total_len);
int pcd_manager_hash_platform_id_measured_data (const struct pcd_manager *manager,
	const struct hash_engine *hash);

int pcd_manager_get_pcd_measured_data (const struct pcd_manager *manager, size_t offset,
	uint8_t *buffer, size_t length, uint32_t *total_len);
int pcd_manager_hash_pcd_measured_data (const struct pcd_manager *manager,
	const struct hash_engine *hash);

/* Internal functions for use by derived types. */
int pcd_manager_init (struct pcd_manager *manager, struct pcd_manager_state *state,
	const struct hash_engine *hash);
int pcd_manager_init_state (const struct pcd_manager *manager);
void pcd_manager_release (const struct pcd_manager *manager);

void pcd_manager_on_pcd_verified (const struct pcd_manager *manager, const struct pcd *pending);
void pcd_manager_on_pcd_activated (const struct pcd_manager *manager);
void pcd_manager_on_clear_active (const struct pcd_manager *manager);
void pcd_manager_on_pcd_activation_request (const struct pcd_manager *manager);


#endif	/* PCD_MANAGER_H_ */
