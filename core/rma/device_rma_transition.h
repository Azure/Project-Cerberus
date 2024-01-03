// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef DEVICE_RMA_TRANSITION_H_
#define DEVICE_RMA_TRANSITION_H_

#include "status/rot_status.h"


/**
 * Interface to apply a device-specific configuration to transition to a test or diagnostic state
 * for RMA.
 */
struct device_rma_transition {
	/**
	 * Configure a device for RMA handling.  While it may not be true in all cases, this transition
	 * is generally expected to be a one-way operation.  It is also likely that a device will be
	 * configured for RMA as a result of this call but the change won't take affect until the device
	 * has been reset.
	 *
	 * @param rma The device handler for configuring RMA state.
	 *
	 * @return 0 if the RMA transition was successful or an error code.
	 */
	int (*config_rma) (const struct device_rma_transition *rma);
};


#define	ROT_MODULE_DEVICE_RMA_TRANSITION_ERROR(code)		ROT_ERROR (ROT_MODULE_DEVICE_RMA_TRANSITION, code)

/**
 * Error codes that can be generated when configuring a device for RMA.
 */
enum {
	DEVICE_RMA_TRANSITION_INVALID_ARGUMENT = ROT_MODULE_DEVICE_RMA_TRANSITION_ERROR (0x00),		/**< Input parameter is null or not valid. */
	DEVICE_RMA_TRANSITION_NO_MEMORY = ROT_MODULE_DEVICE_RMA_TRANSITION_ERROR (0x01),			/**< Memory allocation failed. */
	DEVICE_RMA_TRANSITION_CONFIG_FAIL = ROT_MODULE_DEVICE_RMA_TRANSITION_ERROR (0x02),			/**< Failed to configure the device for RMA. */
};


#endif /* DEVICE_RMA_TRANSITION_H_ */
