// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ATTESTATION_TESTING_H_
#define ATTESTATION_TESTING_H_

#include "testing.h"
#include "riot/riot_key_manager.h"
#include "testing/mock/crypto/x509_mock.h"
#include "testing/mock/keystore/keystore_mock.h"


void attestation_testing_add_int_ca_to_riot_key_manager (CuTest *test,
	struct riot_key_manager *riot, struct keystore_mock *keystore, struct x509_engine_mock *x509);
void attestation_testing_add_root_ca_to_riot_key_manager (CuTest *test,
	struct riot_key_manager *riot, struct keystore_mock *keystore, struct x509_engine_mock *x509);
void attestation_testing_add_aux_certificate (CuTest *test, struct aux_attestation *aux);


#endif /* ATTESTATION_TESTING_H_ */
