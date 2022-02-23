// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MCTP_CONTROL_PROTOCOL_OBSERVER_MOCK_H_
#define MCTP_CONTROL_PROTOCOL_OBSERVER_MOCK_H_

#include "mctp/mctp_control_protocol_observer.h"
#include "mock.h"


/**
 * A mock for MCTP protocol notifications.
 */
struct mctp_control_protocol_observer_mock {
	struct mctp_control_protocol_observer base;				/**< The base observer instance. */
	struct mock mock;								/**< The base mock interface. */
};


int mctp_control_protocol_observer_mock_init (struct mctp_control_protocol_observer_mock *mock);
void mctp_control_protocol_observer_mock_release (struct mctp_control_protocol_observer_mock *mock);

int mctp_control_protocol_observer_mock_validate_and_release (
	struct mctp_control_protocol_observer_mock *mock);


#endif /* MCTP_CONTROL_PROTOCOL_OBSERVER_MOCK_H_ */
