// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "secure_device_unlock_rma.h"
#include "common/unused.h"


int secure_device_unlock_rma_get_unlock_token (const struct secure_device_unlock *unlock,
	uint8_t *token, size_t length)
{
	const struct secure_device_unlock_rma *rma_unlock =
		(const struct secure_device_unlock_rma*) unlock;

	if ((rma_unlock == NULL) || (token == NULL)) {
		return SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT;
	}

	if (length < rma_unlock->csr_length) {
		return SECURE_DEVICE_UNLOCK_SMALL_BUFFER;
	}

	memcpy (token, rma_unlock->dice_csr, rma_unlock->csr_length);

	return rma_unlock->csr_length;
}

int secure_device_unlock_rma_apply_unlock_policy (const struct secure_device_unlock *unlock,
	const uint8_t *policy, size_t length)
{
	const struct secure_device_unlock_rma *rma_unlock =
		(const struct secure_device_unlock_rma*) unlock;
	int status;

	if (rma_unlock == NULL) {
		return SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT;
	}

	status = rma_unlock->token->authenticate (rma_unlock->token, policy, length);
	if (status != 0) {
		return status;
	}

	return rma_unlock->rma->config_rma (rma_unlock->rma);
}

int secure_device_unlock_rma_clear_unlock_policy (const struct secure_device_unlock *unlock)
{
	if (unlock == NULL) {
		return SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT;
	}

	return SECURE_DEVICE_UNLOCK_UNSUPPORTED;
}

/**
 * Initialize a handler for authorized RMA workflows.
 *
 * @param unlock The handler for executing RMA workflows.
 * @param token The token handler for authorizing the device transition to RMA.
 * @param rma Device handler to transition the device for RMA.
 * @param dice_csr The DICE CSR for the device, which will be used as the unlock token.
 * @param csr_length Length of the DICE CSR.
 *
 * @return 0 if the RMA handler was initialized successfully or an error code.
 */
int secure_device_unlock_rma_init (struct secure_device_unlock_rma *unlock,
	const struct rma_unlock_token *token, const struct device_rma_transition *rma,
	const uint8_t *dice_csr, size_t csr_length)
{
	if ((unlock == NULL) || (token == NULL) || (rma == NULL) || (dice_csr == NULL) ||
		(csr_length == 0)) {
		return SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT;
	}

	memset (unlock, 0, sizeof (struct secure_device_unlock_rma));

	unlock->base.get_unlock_token = secure_device_unlock_rma_get_unlock_token;
	unlock->base.apply_unlock_policy = secure_device_unlock_rma_apply_unlock_policy;
	unlock->base.clear_unlock_policy = secure_device_unlock_rma_clear_unlock_policy;

	unlock->token = token;
	unlock->rma = rma;
	unlock->dice_csr = dice_csr;
	unlock->csr_length = csr_length;

	return 0;
}

/**
 * Release the resources used by the RMA handler.
 *
 * @param unlock The RMA handler to release.
 */
void secure_device_unlock_rma_release (const struct secure_device_unlock_rma *unlock)
{
	UNUSED (unlock);
}
