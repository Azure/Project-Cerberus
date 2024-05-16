// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_MEASUREMENTS_MOCK_H_
#define SPDM_MEASUREMENTS_MOCK_H_

#include "mock.h"
#include "spdm/spdm_measurements.h"


/**
 * A mock for handling SPDM measurements.
 */
struct spdm_measurements_mock {
	struct spdm_measurements base;	/**< The base SPDM measurement handler instance. */
	struct mock mock;				/**< The base mock interface. */
};


int spdm_measurements_mock_init (struct spdm_measurements_mock *mock);
void spdm_measurements_mock_release (struct spdm_measurements_mock *mock);

int spdm_measurements_mock_validate_and_release (struct spdm_measurements_mock *mock);


#endif	/* SPDM_MEASUREMENTS_MOCK_H_ */
