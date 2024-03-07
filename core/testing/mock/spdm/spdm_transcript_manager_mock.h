// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_TRANSCRIPT_MANAGER_MOCK_H_
#define SPDM_TRANSCRIPT_MANAGER_MOCK_H_

#include "spdm/spdm_transcript_manager.h"
#include "mock.h"


/**
 * Transcript Manager Mock object.
 */
struct spdm_transcript_manager_mock {
	struct spdm_transcript_manager base;		/**< Transcript Manager instance. */
	struct mock mock;							/**< Transcript Manager mock instance. */
};


int spdm_transcript_manager_mock_init (struct spdm_transcript_manager_mock *mock);

int spdm_transcript_manager_mock_validate_and_release (struct spdm_transcript_manager_mock *mock);


#endif /* SPDM_TRANSCRIPT_MANAGER_MOCK_H_ */
