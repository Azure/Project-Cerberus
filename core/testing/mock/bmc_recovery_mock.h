// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef BMC_RECOVERY_MOCK_H_
#define BMC_RECOVERY_MOCK_H_

#include "host_fw/bmc_recovery.h"
#include "mock.h"


/**
 * A mock BMC recovery state machine.
 */
struct bmc_recovery_mock {
	struct bmc_recovery base;		/**< The base state machine instance. */
	struct mock mock;				/**< The base mock interface. */
};


int bmc_recovery_mock_init (struct bmc_recovery_mock *mock);
void bmc_recovery_mock_release (struct bmc_recovery_mock *mock);

int bmc_recovery_mock_validate_and_release (struct bmc_recovery_mock *mock);


#endif /* BMC_RECOVERY_MOCK_H_ */
