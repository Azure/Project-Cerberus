// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RMA_UNLOCK_TOKEN_MOCK_H_
#define RMA_UNLOCK_TOKEN_MOCK_H_

#include "mock.h"
#include "rma/rma_unlock_token.h"


/**
 * A mock for handling RMA unlock tokens.
 */
struct rma_unlock_token_mock {
	struct rma_unlock_token base;	/**< The base token handler instance. */
	struct mock mock;				/**< The base mock interface. */
};


int rma_unlock_token_mock_init (struct rma_unlock_token_mock *mock);
void rma_unlock_token_mock_release (struct rma_unlock_token_mock *mock);

int rma_unlock_token_mock_validate_and_release (struct rma_unlock_token_mock *mock);


#endif	/* RMA_UNLOCK_TOKEN_MOCK_H_ */
