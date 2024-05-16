// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ECC_ECC_HW_H_
#define ECC_ECC_HW_H_

#include "crypto/ecc.h"
#include "crypto/ecc_hw.h"


/**
 * A context for ECC operations that use a generic hardware accelerator.
 */
struct ecc_engine_ecc_hw {
	struct ecc_engine base;		/**< The base ECC engine. */
	const struct ecc_hw *hw;	/**< Interface to the ECC hardware accelerator. */
};


int ecc_ecc_hw_init (struct ecc_engine_ecc_hw *engine, const struct ecc_hw *hw);
void ecc_ecc_hw_release (const struct ecc_engine_ecc_hw *engine);


#endif	/* ECC_ECC_HW_H_ */
