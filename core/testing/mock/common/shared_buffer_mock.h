// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SHARED_BUFFER_MOCK_H_
#define SHARED_BUFFER_MOCK_H_

#include "mock.h"
#include "common/shared_buffer_interface.h"


/**
 * A mock for arbitrating access to a shared buffer.
 */
struct shared_buffer_mock {
	struct shared_buffer_interface base;	/**< The base shared buffer instance. */
	struct mock mock;						/**< The base mock interface. */
};


int shared_buffer_mock_init (struct shared_buffer_mock *mock);
void shared_buffer_mock_release (struct shared_buffer_mock *mock);

int shared_buffer_mock_validate_and_release (struct shared_buffer_mock *mock);


#endif	/* SHARED_BUFFER_MOCK_H_ */
