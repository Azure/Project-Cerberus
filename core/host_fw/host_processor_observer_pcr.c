// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "host_processor_observer_pcr.h"
#include "host_logging.h"
#include "common/type_cast.h"


/**
 * Update the host FW state PCR.
 *
 * @param observer The observer context to update.
 * @param event The event state to update to.
 */
static void host_processor_observer_pcr_update (struct host_processor_observer_pcr *observer,
	int event)
{
	int status;

	*observer->state = event;
	status = pcr_store_update_versioned_buffer (observer->store, observer->hash, observer->pcr,
		(uint8_t*) observer->state, sizeof (uint32_t), true, 0);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_PCR_UPDATE_ERROR, observer->pcr, status);
	}
}

static void host_processor_observer_pcr_on_bypass_mode (struct host_processor_observer *observer)
{
	host_processor_observer_pcr_update ((struct host_processor_observer_pcr*) observer,
		HOST_PROCESSOR_OBSERVER_PCR_BYPASS);
}

static void host_processor_observer_pcr_on_active_mode (struct host_processor_observer *observer)
{
	host_processor_observer_pcr_update ((struct host_processor_observer_pcr*) observer,
		HOST_PROCESSOR_OBSERVER_PCR_VALID);
}

static void host_processor_observer_pcr_on_recovery (struct host_processor_observer *observer)
{
	host_processor_observer_pcr_update ((struct host_processor_observer_pcr*) observer,
		HOST_PROCESSOR_OBSERVER_PCR_RECOVERY);
}

static void host_processor_observer_pcr_on_inactive_dirty (struct host_state_observer *observer,
	struct host_state_manager *manager)
{
	if (host_state_manager_is_inactive_dirty (manager)) {
		host_processor_observer_pcr_update (
			TO_DERIVED_TYPE (observer, struct host_processor_observer_pcr, base_state),
			HOST_PROCESSOR_OBSERVER_PCR_NOT_VALIDATED);
	}
}

/**
 * Initialize a PCR manager for host validation state.
 *
 * @param host The manager to initialize.
 * @param hash The hash engine to use for PCR calculation.
 * @param store Storage for the PCR that will be managed.
 * @param pcr ID of the PCR entry to manage.
 * @param init_state On init, this will seed the PCR value.  Afterward, this will hold the raw value
 * used to generate the PCR entry.  It is recommended this point to a reset-tolerant memory
 * location.
 *
 * @return 0 if initialization was successful or an error code.
 */
int host_processor_observer_pcr_init (struct host_processor_observer_pcr *host,
	struct hash_engine *hash, struct pcr_store *store, uint16_t pcr, uint32_t *init_state)
{
	int status;

	if ((host == NULL) || (hash == NULL) || (store == NULL) || (init_state == NULL)) {
		return HOST_PROCESSOR_OBSERVER_INVALID_ARGUMENT;
	}

	status = pcr_store_update_versioned_buffer (store, hash, pcr, (uint8_t*) init_state,
		sizeof (uint32_t), true, 0);
	if (status != 0) {
		return status;
	}

	memset (host, 0, sizeof (struct host_processor_observer_pcr));

	host->base.on_bypass_mode = host_processor_observer_pcr_on_bypass_mode;
	host->base.on_active_mode = host_processor_observer_pcr_on_active_mode;
	host->base.on_recovery = host_processor_observer_pcr_on_recovery;

	host->base_state.on_inactive_dirty = host_processor_observer_pcr_on_inactive_dirty;

	host->hash = hash;
	host->store = store;
	host->pcr = pcr;
	host->state = init_state;

	return 0;
}

/**
 * Release a host validation PCR manager.
 *
 * @param host The manager to release.
 */
void host_processor_observer_pcr_release (struct host_processor_observer_pcr *host)
{

}
