// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SECURE_DEVICE_UNLOCK_RMA_H_
#define SECURE_DEVICE_UNLOCK_RMA_H_

#include <stdint.h>
#include <stddef.h>
#include "device_rma_transition.h"
#include "rma_unlock_token.h"
#include "system/secure_device_unlock.h"


/**
 * Handler for authenticating and executing device state transitions for RMA.
 */
struct secure_device_unlock_rma {
	struct secure_device_unlock base;			/**< Base device unlock handler. */
	const struct rma_unlock_token *token;		/**< Handler for authenticating RMA tokens. */
	const struct device_rma_transition *rma;	/**< Device handler to apply the RMA configuration. */
	const uint8_t *dice_csr;					/**< The DICE CSR for the RMA firmware image. */
	size_t csr_length;							/**< Length of the DICE CSR. */
};


int secure_device_unlock_rma_init (struct secure_device_unlock_rma *unlock,
	const struct rma_unlock_token *token, const struct device_rma_transition *rma,
	const uint8_t *dice_csr, size_t csr_length);
void secure_device_unlock_rma_release (const struct secure_device_unlock_rma *unlock);


#endif /* SECURE_DEVICE_UNLOCK_RMA_H_ */
