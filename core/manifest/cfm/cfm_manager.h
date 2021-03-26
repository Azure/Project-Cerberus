// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CFM_MANAGER_H_
#define CFM_MANAGER_H_

#include <stdint.h>
#include <stddef.h>
#include "manifest/manifest_manager.h"
#include "manifest/cfm/cfm.h"
#include "manifest/cfm/cfm_observer.h"
#include "common/observable.h"


/**
 * API for managing a CFM.
 */
struct cfm_manager {
	struct manifest_manager base;					/**< Manifest manager interface */
	struct observable observable;					/**< The manager for CFM observers. */

	/**
	 * Get the active CFM for the protected flash.  The CFM instance must be released with the
	 * manager.
	 *
	 * @param manager The CFM manager to query.
	 *
	 * @return The active CFM or null if there is no active CFM.
	 */
	struct cfm* (*get_active_cfm) (struct cfm_manager *manager);

	/**
	 * Get the CFM that is waiting to be activated.  The CFM instance must be released with the
	 * manager.
	 *
	 * @param manager The CFM manager to query.
	 *
	 * @return The pending CFM or null if there is no pending CFM.
	 */
	struct cfm* (*get_pending_cfm) (struct cfm_manager *manager);

	/**
	 * Release a CFM instance retrieved from the manager.  CFM instances must only be released by
	 * the manager that allocated them.
	 *
	 * @param manager The CFM manager that allocated the CFM instance.
	 * @param cfm The CFM to release.
	 */
	void (*free_cfm) (struct cfm_manager *manager, struct cfm *cfm);
};


int cfm_manager_add_observer (struct cfm_manager *manager, struct cfm_observer *observer);
int cfm_manager_remove_observer (struct cfm_manager *manager, struct cfm_observer *observer);

/* Internal functions for use by derived types. */
int cfm_manager_init (struct cfm_manager *manager, struct hash_engine *hash);
void cfm_manager_release (struct cfm_manager *manager);

void cfm_manager_on_cfm_verified (struct cfm_manager *manager);
void cfm_manager_on_cfm_activated (struct cfm_manager *manager);
void cfm_manager_on_clear_active (struct cfm_manager *manager);

int cfm_manager_get_id_measured_data (struct cfm_manager *manager, size_t offset, uint8_t *buffer,
	size_t length, uint32_t *total_len);
int cfm_manager_get_platform_id_measured_data (struct cfm_manager *manager, size_t offset,
	uint8_t *buffer, size_t length, uint32_t *total_len);
int cfm_manager_get_cfm_measured_data (struct cfm_manager *manager, size_t offset,
	uint8_t *buffer, size_t length, uint32_t *total_len);


#endif /* CFM_MANAGER_H_ */
