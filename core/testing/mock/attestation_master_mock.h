// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ATTESTATION_MASTER_MOCK_H_
#define ATTESTATION_MASTER_MOCK_H_

#include <stdint.h>
#include <stddef.h>
#include "attestation/attestation_master.h"
#include "mock.h"


/**
 * Master attestation manager API mock
 */
struct attestation_master_mock {
	struct attestation_master base;			/**< Master attestation manager instance. */
	struct mock mock;						/**< Mock instance. */
};

int attestation_master_mock_init (struct attestation_master_mock *mock);
void attestation_master_mock_release (struct attestation_master_mock *mock);

int attestation_master_mock_validate_and_release (struct attestation_master_mock *mock);


#endif /* ATTESTATION_MASTER_MOCK_H_ */
