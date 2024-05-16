// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CONFIG_RESET_TESTING_H_
#define CONFIG_RESET_TESTING_H_

#include "testing.h"
#include "attestation/aux_attestation.h"
#include "riot/riot_key_manager.h"
#include "testing/engines/ecc_testing_engine.h"
#include "testing/engines/rsa_testing_engine.h"
#include "testing/engines/x509_testing_engine.h"
#include "testing/mock/keystore/keystore_mock.h"


/**
 * Components necessary for testing reset management of attestation keys.
 */
struct config_reset_testing_keys {
	X509_TESTING_ENGINE x509;			/**< X.509 engine for RIoT certificates. */
	RSA_TESTING_ENGINE rsa;				/**< RSA engine for auxiliary attestation. */
	ECC_TESTING_ENGINE ecc;				/**< ECC engine for auxiliary attestation. */
	struct keystore_mock riot_keystore;	/**< Keystore for RIoT keys. */
	struct riot_key_manager riot;		/**< RIoT keys. */
	struct keystore_mock aux_keystore;	/**< Keystore for attestation keys. */
	struct aux_attestation aux;			/**< Attestation manager. */
};


void config_reset_testing_init_attestation_keys (CuTest *test,
	struct config_reset_testing_keys *keys);
void config_reset_testing_init_attestation_keys_valid_cert_chain (CuTest *test,
	struct config_reset_testing_keys *keys);
void config_reset_testing_release_attestation_keys (CuTest *test,
	struct config_reset_testing_keys *keys);


#endif	/* CONFIG_RESET_TESTING_H_ */
