// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MSG_TRANSPORT_MOCK_H_
#define MSG_TRANSPORT_MOCK_H_

#include <stddef.h>
#include <stdint.h>
#include "mock.h"
#include "cmd_interface/msg_transport.h"


/**
 * Mock for a message transport.
 */
struct msg_transport_mock {
	struct msg_transport base;	/**< Base transport API. */
	struct mock mock;			/**< Mock interface. */
};


int msg_transport_mock_init (struct msg_transport_mock *mock);
void msg_transport_mock_release (struct msg_transport_mock *mock);

int msg_transport_mock_validate_and_release (struct msg_transport_mock *mock);


#endif	/* MSG_TRANSPORT_MOCK_H_ */
