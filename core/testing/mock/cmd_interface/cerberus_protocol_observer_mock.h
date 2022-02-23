// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_PROTOCOL_OBSERVER_MOCK_H_
#define CERBERUS_PROTOCOL_OBSERVER_MOCK_H_

#include "cmd_interface/cerberus_protocol_observer.h"
#include "mock.h"


/**
 * A mock for Cerberus protocol notifications.
 */
struct cerberus_protocol_observer_mock {
	struct cerberus_protocol_observer base;			/**< The base observer instance. */
	struct mock mock;								/**< The base mock interface. */
};


int cerberus_protocol_observer_mock_init (struct cerberus_protocol_observer_mock *mock);
void cerberus_protocol_observer_mock_release (struct cerberus_protocol_observer_mock *mock);

int cerberus_protocol_observer_mock_validate_and_release (
	struct cerberus_protocol_observer_mock *mock);


#endif /* CERBERUS_PROTOCOL_OBSERVER_MOCK_H_ */
