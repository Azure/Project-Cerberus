// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ATTESTATION_RESPONDER_MOCK_H_
#define ATTESTATION_RESPONDER_MOCK_H_

#include <stdint.h>
#include <stddef.h>
#include "attestation/attestation_responder.h"
#include "mock.h"


/**
 * Attestation responder API mock
 */
struct attestation_responder_mock {
	struct attestation_responder base;		/**< Attestation responder instance. */
	struct mock mock;						/**< Mock instance. */
};

int attestation_responder_mock_init (struct attestation_responder_mock *mock);
void attestation_responder_mock_release (struct attestation_responder_mock *mock);

int attestation_responder_mock_validate_and_release (struct attestation_responder_mock *mock);


#endif /* ATTESTATION_RESPONDER_MOCK_H_ */
