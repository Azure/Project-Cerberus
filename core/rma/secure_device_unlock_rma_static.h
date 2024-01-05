// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SECURE_DEVICE_UNLOCK_RMA_STATIC_H_
#define SECURE_DEVICE_UNLOCK_RMA_STATIC_H_

#include "secure_device_unlock_rma.h"


/* Internal functions declared to allow for static initialization. */
int secure_device_unlock_rma_get_unlock_token (const struct secure_device_unlock *unlock,
	uint8_t *token, size_t length);
int secure_device_unlock_rma_apply_unlock_policy (const struct secure_device_unlock *unlock,
	const uint8_t *policy, size_t length);
int secure_device_unlock_rma_clear_unlock_policy (const struct secure_device_unlock *unlock);


/**
 * Constant initializer for the secure unlock API.
 */
#define	SECURE_DEVICE_UNLOCK_RMA_API_INIT	{ \
		.get_unlock_token = secure_device_unlock_rma_get_unlock_token, \
		.apply_unlock_policy = secure_device_unlock_rma_apply_unlock_policy, \
		.clear_unlock_policy = secure_device_unlock_rma_clear_unlock_policy, \
	}


/**
 * Initialize a static instance of a handler for authorized RMA workflows.  This can be a constant
 * instance.
 *
 * There is no validation done on the arguments.
 *
 * @param token_ptr The token handler for authorizing the device transition to RMA.
 * @param rma_ptr Device handler to transition the device for RMA.
 * @param dice_csr_ptr The DICE CSR for the device, which will be used as the unlock token.
 * @param csr_length_arg Length of the DICE CSR.
 */
#define	secure_device_unlock_rma_static_init(token_ptr, rma_ptr, dice_csr_ptr, csr_length_arg)	{ \
		.base = SECURE_DEVICE_UNLOCK_RMA_API_INIT, \
		.token = token_ptr, \
		.rma = rma_ptr, \
		.dice_csr = dice_csr_ptr, \
		.csr_length = csr_length_arg, \
	}


#endif /* SECURE_DEVICE_UNLOCK_RMA_STATIC_H_ */
