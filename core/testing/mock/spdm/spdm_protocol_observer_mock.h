// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_PROTOCOL_OBSERVER_MOCK_H_
#define SPDM_PROTOCOL_OBSERVER_MOCK_H_

#include "mock.h"
#include "spdm/spdm_protocol_observer.h"


/**
 * A mock for system notifications.
 */
struct spdm_protocol_observer_mock {
	struct spdm_protocol_observer base;	/**< The base observer instance. */
	struct mock mock;					/**< The base mock interface. */
};


int spdm_protocol_observer_mock_init (struct spdm_protocol_observer_mock *mock);
void spdm_protocol_observer_mock_release (struct spdm_protocol_observer_mock *mock);

int spdm_protocol_observer_mock_validate_and_release (
	struct spdm_protocol_observer_mock *mock);


#endif	/* SPDM_PROTOCOL_OBSERVER_MOCK_H_ */
