// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef IMPACTFUL_UPDATE_MOCK_H_
#define IMPACTFUL_UPDATE_MOCK_H_

#include "mock.h"
#include "firmware/impactful_update_interface.h"


/**
 * A mock for impactful update handling.
 */
struct impactful_update_mock {
	struct impactful_update_interface base;	/**< The base impactful update instance. */
	struct mock mock;						/**< The base mock instance. */
};


int impactful_update_mock_init (struct impactful_update_mock *mock);
void impactful_update_mock_release (struct impactful_update_mock *mock);

int impactful_update_mock_validate_and_release (struct impactful_update_mock *mock);


#endif	/* IMPACTFUL_UPDATE_MOCK_H_ */
