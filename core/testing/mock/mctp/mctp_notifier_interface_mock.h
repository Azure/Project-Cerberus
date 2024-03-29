// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MCTP_NOTIFIER_INTERFACE_MOCK_H_
#define MCTP_NOTIFIER_INTERFACE_MOCK_H_

#include <stddef.h>
#include <stdint.h>
#include "mock.h"
#include "mctp/mctp_notifier_interface.h"


/**
 * Mock for a mctp notifier interface.
 */
struct mctp_notifier_interface_mock {
	struct mctp_notifier_interface base;	/**< Base mctp notifier API. */
	struct mock mock;						/**< Mock interface. */
};


int mctp_notifier_interface_mock_init (struct mctp_notifier_interface_mock *mock);
void mctp_notifier_interface_mock_release (struct mctp_notifier_interface_mock *mock);

int mctp_notifier_interface_mock_validate_and_release (struct mctp_notifier_interface_mock *mock);


#endif	/* MCTP_NOTIFIER_INTERFACE_MOCK_H_ */
