// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_SECURE_SESSION_MANAGER_MOCK_H_
#define SPDM_SECURE_SESSION_MANAGER_MOCK_H_

#include "spdm/spdm_secure_session_manager.h"
#include "mock.h"


/**
 * Secure Session Manager Mock object.
 */
struct spdm_secure_session_manager_mock {
	struct spdm_secure_session_manager base;	/**< Session Manager instance. */
	struct mock mock;							/**< Session Manager mock instance. */
};


int spdm_secure_session_manager_mock_init (struct spdm_secure_session_manager_mock *mock);

int spdm_secure_session_manager_mock_validate_and_release (
	struct spdm_secure_session_manager_mock *mock);


#endif /* SPDM_SECURE_SESSION_MANAGER_MOCK_H_ */