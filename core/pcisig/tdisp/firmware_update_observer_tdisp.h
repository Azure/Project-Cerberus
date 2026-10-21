// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_UPDATE_OBSERVER_TDISP_H_
#define FIRMWARE_UPDATE_OBSERVER_TDISP_H_

#include "tdisp_driver.h"
#include "tdisp_tdi_context_manager.h"
#include "firmware/firmware_update_observer.h"


/**
 * Observer for firmware updates to block unauthorized updates based on TDISP policy.
 */
struct firmware_update_observer_tdisp {
	struct firmware_update_observer base;					/**< Base notification interface. */
	const struct tdisp_driver *tdisp;						/**< TDISP driver interface. */
	const struct tdisp_tdi_context_manager *tdi_context;	/**< TDI context manager. */
	uint32_t max_tdi_context_count;							/**< Maximum number of TDI contexts. */
};


int firmware_update_observer_tdisp_init (struct firmware_update_observer_tdisp *observer,
	const struct tdisp_driver *tdisp, const struct tdisp_tdi_context_manager *tdi_context,
	uint32_t max_tdi_context_count);
void firmware_update_observer_tdisp_release (
	const struct firmware_update_observer_tdisp *observer);


/* Treat this as an extension of the TDISP driver interface and use error codes from that
 * module. */


#endif	/* FIRMWARE_UPDATE_OBSERVER_TDISP_H_ */
