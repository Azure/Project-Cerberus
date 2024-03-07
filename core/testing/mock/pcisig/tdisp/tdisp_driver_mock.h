// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef TDISP_DRIVER_INTERFACE_MOCK_H_
#define TDISP_DRIVER_INTERFACE_MOCK_H_

#include "pcisig/tdisp/tdisp_driver.h"
#include "mock.h"


/**
 * TDISP driver interface mock
 */
struct tdisp_driver_interface_mock {
	struct tdisp_driver base;			/**< The TDISP driver interface. */
	struct mock mock;					/**< The mock interface. */
};


int tdisp_driver_interface_mock_init (struct tdisp_driver_interface_mock *mock);

int tdisp_driver_interface_mock_validate_and_release (struct tdisp_driver_interface_mock *mock);


#endif /* TDISP_DRIVER_INTERFACE_MOCK_H_ */
