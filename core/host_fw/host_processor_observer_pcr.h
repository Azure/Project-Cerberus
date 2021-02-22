// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_PROCESSOR_OBSERVER_PCR_H_
#define HOST_PROCESSOR_OBSERVER_PCR_H_

#include <stdint.h>
#include "host_processor_observer.h"
#include "host_state_observer.h"
#include "attestation/pcr_store.h"
#include "crypto/hash.h"


/**
 * Seed values to use for recording FW validation states.
 */
enum {
	HOST_PROCESSOR_OBSERVER_PCR_INIT = 0xffffffff,	/**< Initial state before any validation has happened. */
	HOST_PROCESSOR_OBSERVER_PCR_VALID = 0,			/**< The FW has been validated and host is protected. */
	HOST_PROCESSOR_OBSERVER_PCR_BYPASS,				/**< The host is running in bypass mode. */
	HOST_PROCESSOR_OBSERVER_PCR_RECOVERY,			/**< The host recovery image is running. */
	HOST_PROCESSOR_OBSERVER_PCR_NOT_VALIDATED,		/**< The host firmware is in an unknown state. */
};

/**
 * Handler for updating the PCR entry that reports host FW validation state.
 */
struct host_processor_observer_pcr {
	struct host_processor_observer base;	/**< Base observer for receiving notifications. */
	struct host_state_observer base_state;	/**< Base observer for host state notifications. */
	struct pcr_store *store;				/**< Storage for the PCR to manage. */
	struct hash_engine *hash;				/**< Hash engine for PCR calculation. */
	uint32_t *state;						/**< Storage for the raw state value. */
	uint16_t pcr;							/**< PCR measurement ID to manage. */
};


int host_processor_observer_pcr_init (struct host_processor_observer_pcr *host,
	struct hash_engine *hash, struct pcr_store *store, uint16_t pcr, uint32_t *init_state);
void host_processor_observer_pcr_release (struct host_processor_observer_pcr *host);


#endif /* HOST_PROCESSOR_OBSERVER_PCR_H_ */
