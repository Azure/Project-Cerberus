// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_PERSISTENT_CONTEXT_MOCK_H_
#define SPDM_PERSISTENT_CONTEXT_MOCK_H_

#include "mock.h"
#include "spdm/spdm_persistent_context.h"


/**
 * SPDM persistent state interface mock
 */
struct spdm_persistent_context_interface_mock {
	struct spdm_persistent_context_interface base;	/**< SPDM persistent context interface */
	struct mock mock;								/**< Mock interface */
};


int spdm_persistent_context_interface_mock_init (
	struct spdm_persistent_context_interface_mock *mock);
int spdm_persistent_context_interface_mock_validate_and_release (
	struct spdm_persistent_context_interface_mock *mock);


#endif	/* SPDM_PERSISTENT_CONTEXT_MOCK_H_ */
