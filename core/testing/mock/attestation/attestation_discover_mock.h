// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ATTESTATION_DISCOVER_MOCK_H_
#define ATTESTATION_DISCOVER_MOCK_H_

#include <stddef.h>
#include <stdint.h>
#include "mock.h"
#include "attestation/attestation_discover.h"


/**
 * Attestation discover API mock
 */
struct attestation_discover_mock {
	struct attestation_discover base;	/**< Attestation discover instance. */
	struct mock mock;					/**< Mock instance. */
};


int attestation_discover_mock_init (struct attestation_discover_mock *mock);
void attestation_discover_mock_release (struct attestation_discover_mock *mock);

int attestation_discover_mock_validate_and_release (struct attestation_discover_mock *mock);


#endif	/* ATTESTATION_DISCOVER_MOCK_H_ */
