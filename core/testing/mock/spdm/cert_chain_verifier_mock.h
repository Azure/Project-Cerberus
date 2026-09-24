// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERT_CHAIN_VERIFIER_MOCK_H_
#define CERT_CHAIN_VERIFIER_MOCK_H_

#include "mock.h"
#include "spdm/cert_chain_verifier_interface.h"


/**
 * A mock for the certificate chain verifier API.
 */
struct cert_chain_verifier_mock {
	struct cert_chain_verifier base;	/**< The base certificate chain verifier API. */
	struct mock mock;					/**< The base mock interface. */
};


int cert_chain_verifier_mock_init (struct cert_chain_verifier_mock *mock);
void cert_chain_verifier_mock_release (struct cert_chain_verifier_mock *mock);

int cert_chain_verifier_mock_validate_and_release (struct cert_chain_verifier_mock *mock);


#endif	/* CERT_CHAIN_VERIFIER_MOCK_H_ */
