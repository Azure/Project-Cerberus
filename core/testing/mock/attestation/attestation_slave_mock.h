// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ATTESTATION_SLAVE_MOCK_H_
#define ATTESTATION_SLAVE_MOCK_H_

#include <stdint.h>
#include <stddef.h>
#include "attestation/attestation_slave.h"
#include "mock.h"


/**
 * Slave attestation manager API mock
 */
struct attestation_slave_mock {
	struct attestation_slave base;			/**< Slave attestation manager instance. */
	struct mock mock;						/**< Mock instance. */
};

int attestation_slave_mock_init (struct attestation_slave_mock *mock);
void attestation_slave_mock_release (struct attestation_slave_mock *mock);

int attestation_slave_mock_validate_and_release (struct attestation_slave_mock *mock);


#endif /* ATTESTATION_SLAVE_MOCK_H_ */
