// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_CERTIFICATE_CHAIN_MOCK_H_
#define SPDM_CERTIFICATE_CHAIN_MOCK_H_

#include "mock.h"
#include "spdm/spdm_certificate_chain.h"


/**
 * A mock for handling an SPDM certificate chain.
 */
struct spdm_certificate_chain_mock {
	struct spdm_certificate_chain base;	/**< The base SPDM certificate chain instance. */
	struct mock mock;					/**< The base mock interface. */
};


int spdm_certificate_chain_mock_init (struct spdm_certificate_chain_mock *mock);
void spdm_certificate_chain_mock_release (struct spdm_certificate_chain_mock *mock);

int spdm_certificate_chain_mock_validate_and_release (struct spdm_certificate_chain_mock *mock);


#endif	/* SPDM_CERTIFICATE_CHAIN_MOCK_H_ */
