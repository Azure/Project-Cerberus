// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ECDH_KAT_H_
#define ECDH_KAT_H_

#include "crypto/ecc.h"
#include "crypto/ecc_hw.h"
#include "crypto/ecdh.h"


int ecdh_kat_run_self_test_p256 (const struct ecc_engine *ecc);
int ecdh_kat_run_self_test_p384 (const struct ecc_engine *ecc);
int ecdh_kat_run_self_test_p521 (const struct ecc_engine *ecc);

int ecdh_hw_kat_run_self_test_p256 (const struct ecc_hw *ecc);
int ecdh_hw_kat_run_self_test_p384 (const struct ecc_hw *ecc);
int ecdh_hw_kat_run_self_test_p521 (const struct ecc_hw *ecc);


#endif	/* ECDSA_KAT_H_ */
