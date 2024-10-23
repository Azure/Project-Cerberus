// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef TDISP_TDI_CONTEXT_MANAGER_MOCK_H_
#define TDISP_TDI_CONTEXT_MANAGER_MOCK_H_

#include "mock.h"
#include "pcisig/tdisp/tdisp_tdi_context_manager.h"


/**
 * TDISP TDI context manager interface mock
 */
struct tdisp_tdi_context_manager_mock {
	struct tdisp_tdi_context_manager base;	/**< TDISP TDI context manager interface */
	struct mock mock;						/**< Mock interface */
};


int tdisp_tdi_context_manager_mock_init (struct tdisp_tdi_context_manager_mock *mock);
int tdisp_tdi_context_manager_mock_validate_and_release (
	struct tdisp_tdi_context_manager_mock *mock);


#endif	// TDISP_TDI_CONTEXT_MANAGER_MOCK_H_
