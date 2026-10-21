// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MMIO_REGISTER_BLOCK_MOCK_H_
#define MMIO_REGISTER_BLOCK_MOCK_H_

#include "mock.h"
#include "mmio/mmio_register_block.h"


/**
 * MMIO register block interface mock
 */
struct mmio_register_block_mock {
	struct mmio_register_block base;	/**< MMIO register block interface */
	struct mock mock;					/**< Mock interface */
};


int mmio_register_block_mock_init (struct mmio_register_block_mock *mock);
int mmio_register_block_mock_validate_and_release (struct mmio_register_block_mock *mock);


#endif	// MMIO_REGISTER_BLOCK_MOCK_H_
