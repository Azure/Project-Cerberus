// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZED_DATA_MOCK_H_
#define AUTHORIZED_DATA_MOCK_H_

#include "mock.h"
#include "common/authorized_data.h"


/**
 * A mock for handling authorized data.
 */
struct authorized_data_mock {
	struct authorized_data base;	/**< The base authorized data handler instance. */
	struct mock mock;				/**< The base mock interface. */
};


int authorized_data_mock_init (struct authorized_data_mock *mock);
void authorized_data_mock_release (struct authorized_data_mock *mock);

int authorized_data_mock_validate_and_release (struct authorized_data_mock *mock);


#endif	/* AUTHORIZED_DATA_MOCK_H_ */
