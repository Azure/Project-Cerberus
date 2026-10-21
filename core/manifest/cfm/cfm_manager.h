// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CFM_MANAGER_H_
#define CFM_MANAGER_H_

#include <stddef.h>
#include <stdint.h>
#include "common/observable.h"
#include "manifest/cfm/cfm.h"
#include "manifest/cfm/cfm_observer.h"
#include "manifest/manifest_manager.h"


/**
 * Variable context for managing a single CFM.
 */
struct cfm_manager_state {
	struct observable observable;	/**< The manager for CFM observers. */
};

/**
 * API for managing a CFM.
 */
struct cfm_manager {
	struct manifest_manager base;	/**< Manifest manager interface */

	/**
	 * Get the active CFM for the protected flash.  The CFM instance must be released with the
	 * manager.
	 *
	 * @param manager The CFM manager to query.
	 *
	 * @return The active CFM or null if there is no active CFM.
	 */
	const struct cfm* (*get_active_cfm) (const struct cfm_manager *manager);

	/**
	 * Get the CFM that is waiting to be activated.  The CFM instance must be released with the
	 * manager.
	 *
	 * @param manager The CFM manager to query.
	 *
	 * @return The pending CFM or null if there is no pending CFM.
	 */
	const struct cfm* (*get_pending_cfm) (const struct cfm_manager *manager);

	/**
	 * Release a CFM instance retrieved from the manager.  CFM instances must only be released by
	 * the manager that allocated them.
	 *
	 * @param manager The CFM manager that allocated the CFM instance.
	 * @param cfm The CFM to release.
	 */
	void (*free_cfm) (const struct cfm_manager *manager, const struct cfm *cfm);

	struct cfm_manager_state *state;	/**< Variable context for CFM management. */
};


int cfm_manager_add_observer (const struct cfm_manager *manager,
	const struct cfm_observer *observer);
int cfm_manager_remove_observer (const struct cfm_manager *manager,
	const struct cfm_observer *observer);

int cfm_manager_get_id_measured_data (const struct cfm_manager *manager, size_t offset,
	uint8_t *buffer, size_t length, uint32_t *total_len);
int cfm_manager_hash_id_measured_data (const struct cfm_manager *manager,
	const struct hash_engine *hash);

int cfm_manager_get_platform_id_measured_data (const struct cfm_manager *manager, size_t offset,
	uint8_t *buffer, size_t length, uint32_t *total_len);
int cfm_manager_hash_platform_id_measured_data (const struct cfm_manager *manager,
	const struct hash_engine *hash);

int cfm_manager_get_cfm_measured_data (const struct cfm_manager *manager, size_t offset,
	uint8_t *buffer, size_t length, uint32_t *total_len);
int cfm_manager_hash_cfm_measured_data (const struct cfm_manager *manager,
	const struct hash_engine *hash);

/* Internal functions for use by derived types. */
int cfm_manager_init (struct cfm_manager *manager, struct cfm_manager_state *state,
	const struct hash_engine *hash);
int cfm_manager_init_state (const struct cfm_manager *manager);
void cfm_manager_release (const struct cfm_manager *manager);

void cfm_manager_on_cfm_verified (const struct cfm_manager *manager);
void cfm_manager_on_cfm_activated (const struct cfm_manager *manager);
void cfm_manager_on_clear_active (const struct cfm_manager *manager);
void cfm_manager_on_cfm_activation_request (const struct cfm_manager *manager);


#endif	/* CFM_MANAGER_H_ */
