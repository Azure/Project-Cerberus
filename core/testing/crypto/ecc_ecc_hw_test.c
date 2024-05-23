// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "asn1/ecc_der_util.h"
#include "crypto/ecc_ecc_hw.h"
#include "crypto/ecc_ecc_hw_static.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/crypto/rsa_testing.h"
#include "testing/crypto/signature_testing.h"
#include "testing/mock/crypto/ecc_hw_mock.h"
#include "testing/mock/crypto/ecc_mock.h"
#include "testing/mock/crypto/rng_mock.h"


TEST_SUITE_LABEL ("ecc_ecc_hw");


/*******************
 * Test cases
 *******************/

static void ecc_ecc_hw_test_init (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, engine.base.init_key_pair);
	CuAssertPtrNotNull (test, engine.base.init_public_key);
	CuAssertPtrNotNull (test, engine.base.generate_derived_key_pair);
	CuAssertPtrNotNull (test, engine.base.generate_key_pair);
	CuAssertPtrNotNull (test, engine.base.release_key_pair);
	CuAssertPtrNotNull (test, engine.base.get_signature_max_length);
	CuAssertPtrNotNull (test, engine.base.get_private_key_der);
	CuAssertPtrNotNull (test, engine.base.get_public_key_der);
	CuAssertPtrNotNull (test, engine.base.sign);
	CuAssertPtrNotNull (test, engine.base.verify);
	CuAssertPtrNotNull (test, engine.base.get_shared_secret_max_length);
	CuAssertPtrNotNull (test, engine.base.compute_shared_secret);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_init_null (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (NULL, &hw.base, NULL);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = ecc_ecc_hw_init (&engine, NULL, NULL);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);
}

static void ecc_ecc_hw_test_release_null (CuTest *test)
{
	TEST_START;

	ecc_ecc_hw_release (NULL);
}

static void ecc_ecc_hw_test_public_key_init_key_pair_and_verify (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, NULL,
		&pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SIG_HASH_TEST),
		MOCK_ARG (SIG_HASH_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_public_key_init_key_pair_and_verify_no_pubkey (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_NO_PUBKEY_DER,
		ECC_PRIVKEY_NO_PUBKEY_DER_LEN, NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SIG_HASH_TEST),
		MOCK_ARG (SIG_HASH_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_public_key_init_key_pair_and_verify_extra_buffer (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t privkey[ECC_PRIVKEY_DER_LEN + 20];

	TEST_START;

	memcpy (privkey, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN);

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, privkey, sizeof (privkey), NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SIG_HASH_TEST),
		MOCK_ARG (SIG_HASH_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
static void ecc_ecc_hw_test_public_key_init_key_pair_and_verify_p384 (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PRIVKEY, ECC384_PRIVKEY_LEN), MOCK_ARG (ECC384_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC384_PUBKEY_POINT, sizeof (ECC384_PUBKEY_POINT),
		-1);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC384_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC384_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SHA384_TEST_HASH),
		MOCK_ARG (SHA384_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_public_key_init_key_pair_and_verify_p384_no_pubkey (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PRIVKEY, ECC384_PRIVKEY_LEN), MOCK_ARG (ECC384_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC384_PUBKEY_POINT, sizeof (ECC384_PUBKEY_POINT),
		-1);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC384_PRIVKEY_NO_PUBKEY_DER,
		ECC384_PRIVKEY_NO_PUBKEY_DER_LEN, NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC384_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC384_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SHA384_TEST_HASH),
		MOCK_ARG (SHA384_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_public_key_init_key_pair_and_verify_p384_extra_buffer (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t privkey[ECC384_PRIVKEY_DER_LEN + 20];

	TEST_START;

	memcpy (privkey, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN);

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PRIVKEY, ECC384_PRIVKEY_LEN), MOCK_ARG (ECC384_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC384_PUBKEY_POINT, sizeof (ECC384_PUBKEY_POINT),
		-1);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, privkey, sizeof (privkey), NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC384_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC384_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SHA384_TEST_HASH),
		MOCK_ARG (SHA384_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
static void ecc_ecc_hw_test_public_key_init_key_pair_and_verify_p521 (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY, ECC521_PRIVKEY_LEN), MOCK_ARG (ECC521_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC521_PUBKEY_POINT, sizeof (ECC521_PUBKEY_POINT),
		-1);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN,
		NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC521_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC521_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SHA512_TEST_HASH),
		MOCK_ARG (SHA512_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH,
		ECC521_SIGNATURE_TEST, ECC521_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_public_key_init_key_pair_and_verify_p521_no_pubkey (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY, ECC521_PRIVKEY_LEN), MOCK_ARG (ECC521_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC521_PUBKEY_POINT, sizeof (ECC521_PUBKEY_POINT),
		-1);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC521_PRIVKEY_NO_PUBKEY_DER,
		ECC521_PRIVKEY_NO_PUBKEY_DER_LEN, NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC521_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC521_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SHA512_TEST_HASH),
		MOCK_ARG (SHA512_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH,
		ECC521_SIGNATURE_TEST, ECC521_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_public_key_init_key_pair_and_verify_p521_extra_buffer (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t privkey[ECC521_PRIVKEY_DER_LEN + 20];

	TEST_START;

	memcpy (privkey, ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN);

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY, ECC521_PRIVKEY_LEN), MOCK_ARG (ECC521_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC521_PUBKEY_POINT, sizeof (ECC521_PUBKEY_POINT),
		-1);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, privkey, sizeof (privkey), NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC521_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC521_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SHA512_TEST_HASH),
		MOCK_ARG (SHA512_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH,
		ECC521_SIGNATURE_TEST, ECC521_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}
#endif

static void ecc_ecc_hw_test_public_key_init_key_pair_and_verify_bad_sig (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, NULL,
		&pub_key);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, ECC_HW_ECDSA_BAD_SIGNATURE,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC_SIGNATURE_BAD_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SIG_HASH_TEST),
		MOCK_ARG (SIG_HASH_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_BAD, ECC_SIG_BAD_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_private_key_init_key_pair_and_sign (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t out[ECC_TESTING_ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_sign, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_PTR (SIG_HASH_TEST), MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR (NULL),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 5, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (ECC_SIGNATURE_TEST_STRUCT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	// The output is deterministic for this implementation.
	CuAssertIntEquals (test, ECC_SIG_TEST_LEN, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);
	CuAssertPtrEquals (test, NULL, priv_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_public_key_init_key_pair_and_sign (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC_TESTING_ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, NULL,
		&pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.sign (&engine.base, (struct ecc_private_key*) &pub_key, SIG_HASH_TEST,
		SIG_HASH_LEN, out, sizeof (out));
	CuAssertIntEquals (test, ECC_ENGINE_NOT_PRIVATE_KEY, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_init_key_pair_and_sign_and_verify (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_TESTING_ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_sign, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_PTR (SIG_HASH_TEST), MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR (NULL),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 5, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (ECC_SIGNATURE_TEST_STRUCT), -1);

	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	// The output is deterministic for this implementation.
	CuAssertIntEquals (test, ECC_SIG_TEST_LEN, out_len);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SIG_HASH_TEST),
		MOCK_ARG (SIG_HASH_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
	CuAssertPtrEquals (test, NULL, priv_key.context);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_init_key_pair_and_sign_and_verify_no_pubkey (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_TESTING_ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_NO_PUBKEY_DER,
		ECC_PRIVKEY_NO_PUBKEY_DER_LEN, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_sign, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_PTR (SIG_HASH_TEST), MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR (NULL),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 5, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (ECC_SIGNATURE_TEST_STRUCT), -1);

	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	// The output is deterministic for this implementation.
	CuAssertIntEquals (test, ECC_SIG_TEST_LEN, out_len);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SIG_HASH_TEST),
		MOCK_ARG (SIG_HASH_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
	CuAssertPtrEquals (test, NULL, priv_key.context);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_init_key_pair_and_sign_and_verify_extra_buffer (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_TESTING_ECC256_DSA_MAX_LENGTH * 2];
	uint8_t privkey[ECC_PRIVKEY_DER_LEN * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	memcpy (privkey, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, privkey, sizeof (privkey), &priv_key,
		&pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_sign, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_PTR (SIG_HASH_TEST), MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR (NULL),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 5, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (ECC_SIGNATURE_TEST_STRUCT), -1);

	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	// The output is deterministic for this implementation.
	CuAssertIntEquals (test, ECC_SIG_TEST_LEN, out_len);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SIG_HASH_TEST),
		MOCK_ARG (SIG_HASH_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
	CuAssertPtrEquals (test, NULL, priv_key.context);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
static void ecc_ecc_hw_test_init_key_pair_and_sign_and_verify_p384 (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_TESTING_ECC384_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PRIVKEY, ECC384_PRIVKEY_LEN), MOCK_ARG (ECC384_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC384_PUBKEY_POINT, sizeof (ECC384_PUBKEY_POINT),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_sign, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PRIVKEY, ECC384_PRIVKEY_LEN), MOCK_ARG (ECC384_PRIVKEY_LEN),
		MOCK_ARG_PTR (SHA384_TEST_HASH), MOCK_ARG (SHA384_HASH_LENGTH), MOCK_ARG_PTR (NULL),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 5, &ECC384_SIGNATURE_TEST_STRUCT,
		sizeof (ECC384_SIGNATURE_TEST_STRUCT), -1);

	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.sign (&engine.base, &priv_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH, out,
		sizeof (out));
	// The output is deterministic for this implementation.
	CuAssertIntEquals (test, ECC384_SIG_TEST_LEN, out_len);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC384_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC384_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SHA384_TEST_HASH),
		MOCK_ARG (SHA384_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH, out,
		out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
	CuAssertPtrEquals (test, NULL, priv_key.context);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_init_key_pair_and_sign_and_verify_p384_no_pubkey (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_TESTING_ECC384_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PRIVKEY, ECC384_PRIVKEY_LEN), MOCK_ARG (ECC384_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC384_PUBKEY_POINT, sizeof (ECC384_PUBKEY_POINT),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC384_PRIVKEY_NO_PUBKEY_DER,
		ECC384_PRIVKEY_NO_PUBKEY_DER_LEN, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_sign, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PRIVKEY, ECC384_PRIVKEY_LEN), MOCK_ARG (ECC384_PRIVKEY_LEN),
		MOCK_ARG_PTR (SHA384_TEST_HASH), MOCK_ARG (SHA384_HASH_LENGTH), MOCK_ARG_PTR (NULL),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 5, &ECC384_SIGNATURE_TEST_STRUCT,
		sizeof (ECC384_SIGNATURE_TEST_STRUCT), -1);

	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.sign (&engine.base, &priv_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH, out,
		sizeof (out));
	// The output is deterministic for this implementation.
	CuAssertIntEquals (test, ECC384_SIG_TEST_LEN, out_len);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC384_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC384_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SHA384_TEST_HASH),
		MOCK_ARG (SHA384_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH, out,
		out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
	CuAssertPtrEquals (test, NULL, priv_key.context);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_init_key_pair_and_sign_and_verify_p384_extra_buffer (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_TESTING_ECC384_DSA_MAX_LENGTH * 2];
	uint8_t privkey[ECC384_PRIVKEY_DER_LEN * 2];

	TEST_START;

	memcpy (privkey, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN);

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PRIVKEY, ECC384_PRIVKEY_LEN), MOCK_ARG (ECC384_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC384_PUBKEY_POINT, sizeof (ECC384_PUBKEY_POINT),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, privkey, sizeof (privkey), &priv_key,
		&pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_sign, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PRIVKEY, ECC384_PRIVKEY_LEN), MOCK_ARG (ECC384_PRIVKEY_LEN),
		MOCK_ARG_PTR (SHA384_TEST_HASH), MOCK_ARG (SHA384_HASH_LENGTH), MOCK_ARG_PTR (NULL),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 5, &ECC384_SIGNATURE_TEST_STRUCT,
		sizeof (ECC384_SIGNATURE_TEST_STRUCT), -1);

	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.sign (&engine.base, &priv_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH, out,
		sizeof (out));
	// The output is deterministic for this implementation.
	CuAssertIntEquals (test, ECC384_SIG_TEST_LEN, out_len);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC384_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC384_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SHA384_TEST_HASH),
		MOCK_ARG (SHA384_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH, out,
		out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
	CuAssertPtrEquals (test, NULL, priv_key.context);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
static void ecc_ecc_hw_test_init_key_pair_and_sign_and_verify_p521 (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_TESTING_ECC521_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY, ECC521_PRIVKEY_LEN), MOCK_ARG (ECC521_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC521_PUBKEY_POINT, sizeof (ECC521_PUBKEY_POINT),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_sign, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY, ECC521_PRIVKEY_LEN), MOCK_ARG (ECC521_PRIVKEY_LEN),
		MOCK_ARG_PTR (SHA512_TEST_HASH), MOCK_ARG (SHA512_HASH_LENGTH), MOCK_ARG_PTR (NULL),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 5, &ECC521_SIGNATURE_TEST_STRUCT,
		sizeof (ECC521_SIGNATURE_TEST_STRUCT), -1);

	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.sign (&engine.base, &priv_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH, out,
		sizeof (out));
	// The output is deterministic for this implementation.
	CuAssertIntEquals (test, ECC521_SIG_TEST_LEN, out_len);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC521_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC521_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SHA512_TEST_HASH),
		MOCK_ARG (SHA512_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH, out,
		out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
	CuAssertPtrEquals (test, NULL, priv_key.context);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_init_key_pair_and_sign_and_verify_p521_no_pubkey (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_TESTING_ECC521_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY, ECC521_PRIVKEY_LEN), MOCK_ARG (ECC521_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC521_PUBKEY_POINT, sizeof (ECC521_PUBKEY_POINT),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC521_PRIVKEY_NO_PUBKEY_DER,
		ECC521_PRIVKEY_NO_PUBKEY_DER_LEN, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_sign, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY, ECC521_PRIVKEY_LEN), MOCK_ARG (ECC521_PRIVKEY_LEN),
		MOCK_ARG_PTR (SHA512_TEST_HASH), MOCK_ARG (SHA512_HASH_LENGTH), MOCK_ARG_PTR (NULL),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 5, &ECC521_SIGNATURE_TEST_STRUCT,
		sizeof (ECC521_SIGNATURE_TEST_STRUCT), -1);

	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.sign (&engine.base, &priv_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH, out,
		sizeof (out));
	// The output is deterministic for this implementation.
	CuAssertIntEquals (test, ECC521_SIG_TEST_LEN, out_len);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC521_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC521_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SHA512_TEST_HASH),
		MOCK_ARG (SHA512_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH, out,
		out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
	CuAssertPtrEquals (test, NULL, priv_key.context);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_init_key_pair_and_sign_and_verify_p521_no_leading_zero (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_TESTING_ECC521_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY, ECC521_PRIVKEY_LEN), MOCK_ARG (ECC521_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC521_PUBKEY_POINT, sizeof (ECC521_PUBKEY_POINT),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC521_PRIVKEY_DER_NO_LEADING_ZERO,
		ECC521_PRIVKEY_DER_NO_LEADING_ZERO_LEN, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_sign, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY, ECC521_PRIVKEY_LEN), MOCK_ARG (ECC521_PRIVKEY_LEN),
		MOCK_ARG_PTR (SHA512_TEST_HASH), MOCK_ARG (SHA512_HASH_LENGTH), MOCK_ARG_PTR (NULL),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 5, &ECC521_SIGNATURE_TEST_STRUCT,
		sizeof (ECC521_SIGNATURE_TEST_STRUCT), -1);

	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.sign (&engine.base, &priv_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH, out,
		sizeof (out));
	// The output is deterministic for this implementation.
	CuAssertIntEquals (test, ECC521_SIG_TEST_LEN, out_len);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC521_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC521_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SHA512_TEST_HASH),
		MOCK_ARG (SHA512_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH, out,
		out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
	CuAssertPtrEquals (test, NULL, priv_key.context);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_init_key_pair_and_sign_and_verify_p521_extra_buffer (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_TESTING_ECC521_DSA_MAX_LENGTH * 2];
	uint8_t privkey[ECC521_PRIVKEY_DER_LEN * 2];

	TEST_START;

	memcpy (privkey, ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN);

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY, ECC521_PRIVKEY_LEN), MOCK_ARG (ECC521_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC521_PUBKEY_POINT, sizeof (ECC521_PUBKEY_POINT),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, privkey, sizeof (privkey), &priv_key,
		&pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_sign, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY, ECC521_PRIVKEY_LEN), MOCK_ARG (ECC521_PRIVKEY_LEN),
		MOCK_ARG_PTR (SHA512_TEST_HASH), MOCK_ARG (SHA512_HASH_LENGTH), MOCK_ARG_PTR (NULL),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 5, &ECC521_SIGNATURE_TEST_STRUCT,
		sizeof (ECC521_SIGNATURE_TEST_STRUCT), -1);

	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.sign (&engine.base, &priv_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH, out,
		sizeof (out));
	// The output is deterministic for this implementation.
	CuAssertIntEquals (test, ECC521_SIG_TEST_LEN, out_len);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC521_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC521_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SHA512_TEST_HASH),
		MOCK_ARG (SHA512_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH, out,
		out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
	CuAssertPtrEquals (test, NULL, priv_key.context);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}
#endif

static void ecc_ecc_hw_test_init_key_pair_and_sign_with_public_key (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC_TESTING_ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.sign (&engine.base, (struct ecc_private_key*) &pub_key, SIG_HASH_TEST,
		SIG_HASH_LEN, out, sizeof (out));
	CuAssertIntEquals (test, ECC_ENGINE_NOT_PRIVATE_KEY, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
	CuAssertPtrEquals (test, NULL, priv_key.context);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_init_key_pair_no_keys (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, NULL,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_init_key_pair_null (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (NULL, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,	&priv_key,
		&pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.init_key_pair (&engine.base, NULL, ECC_PRIVKEY_DER_LEN, &priv_key,
		&pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, 0, &priv_key, &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_init_key_pair_with_public_key (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, NULL,
		&pub_key);
	CuAssertIntEquals (test, ECC_DER_UTIL_UNEXPECTED_TAG, status);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_init_key_pair_with_rsa_key (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, NULL,
		&pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_NOT_EC_KEY, status);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_init_public_key_and_verify (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SIG_HASH_TEST),
		MOCK_ARG (SIG_HASH_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_init_public_key_and_verify_extra_buffer (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	uint8_t pubkey[ECC_PUBKEY_DER_LEN * 2];
	uint8_t signature[ECC_SIG_TEST_LEN * 2];
	int status;

	TEST_START;

	memcpy (pubkey, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);
	memcpy (signature, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, pubkey, sizeof (pubkey), &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SIG_HASH_TEST),
		MOCK_ARG (SIG_HASH_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN, signature,
		sizeof (signature));
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
static void ecc_ecc_hw_test_init_public_key_and_verify_p384 (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, ECC384_PUBKEY_DER, ECC384_PUBKEY_DER_LEN,
		&pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC384_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC384_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SHA384_TEST_HASH),
		MOCK_ARG (SHA384_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_init_public_key_and_verify_p384_extra_buffer (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	uint8_t pubkey[ECC384_PUBKEY_DER_LEN * 2];
	uint8_t signature[ECC384_SIG_TEST_LEN * 2];
	int status;

	TEST_START;

	memcpy (pubkey, ECC384_PUBKEY_DER, ECC384_PUBKEY_DER_LEN);
	memcpy (signature, ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN);

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, pubkey, sizeof (pubkey), &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC384_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC384_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SHA384_TEST_HASH),
		MOCK_ARG (SHA384_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH,
		signature, sizeof (signature));
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
static void ecc_ecc_hw_test_init_public_key_and_verify_p521 (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, ECC521_PUBKEY_DER, ECC521_PUBKEY_DER_LEN,
		&pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC521_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC521_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SHA512_TEST_HASH),
		MOCK_ARG (SHA512_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH,
		ECC521_SIGNATURE_TEST, ECC521_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_init_public_key_and_verify_p521_extra_buffer (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	uint8_t pubkey[ECC521_PUBKEY_DER_LEN * 2];
	uint8_t signature[ECC521_SIG_TEST_LEN * 2];
	int status;

	TEST_START;

	memcpy (pubkey, ECC521_PUBKEY_DER, ECC521_PUBKEY_DER_LEN);
	memcpy (signature, ECC521_SIGNATURE_TEST, ECC521_SIG_TEST_LEN);

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, pubkey, sizeof (pubkey), &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC521_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC521_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SHA512_TEST_HASH),
		MOCK_ARG (SHA512_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH,
		signature, sizeof (signature));
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}
#endif

static void ecc_ecc_hw_test_init_public_key_and_verify_bad_sig (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&pub_key);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, ECC_HW_ECDSA_BAD_SIGNATURE,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC_SIGNATURE_BAD_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SIG_HASH_TEST),
		MOCK_ARG (SIG_HASH_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_BAD, ECC_SIG_BAD_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_init_public_key_null (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (NULL, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,	&pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.init_public_key (&engine.base, NULL, ECC_PUBKEY_DER_LEN, &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.init_public_key (&engine.base, ECC_PUBKEY_DER, 0, &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.init_public_key (&engine.base, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,	NULL);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_init_public_key_with_private_key (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&pub_key);
	CuAssertIntEquals (test, ECC_DER_UTIL_UNEXPECTED_TAG, status);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_init_public_key_with_rsa_key (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, RSA_PUBKEY_DER, RSA_PUBKEY_DER_LEN,
		&pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_NOT_EC_KEY, status);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_public_key_generate_derived_key_pair_and_verify (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SIG_HASH_TEST),
		MOCK_ARG (SIG_HASH_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_public_key_generate_derived_key_pair_and_verify_p384 (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PRIVKEY, ECC384_PRIVKEY_LEN), MOCK_ARG (ECC384_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC384_PUBKEY_POINT, sizeof (ECC384_PUBKEY_POINT),
		-1);

	CuAssertIntEquals (test, 0, status);
#endif

	status = engine.base.generate_derived_key_pair (&engine.base, ECC384_PRIVKEY,
		ECC384_PRIVKEY_LEN, NULL, &pub_key);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC384_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC384_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SHA384_TEST_HASH),
		MOCK_ARG (SHA384_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);
#else
	CuAssertIntEquals (test, ECC_ENGINE_UNSUPPORTED_KEY_LENGTH, status);
#endif

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_public_key_generate_derived_key_pair_and_verify_p521 (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY, ECC521_PRIVKEY_LEN), MOCK_ARG (ECC521_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC521_PUBKEY_POINT, sizeof (ECC521_PUBKEY_POINT),
		-1);

	CuAssertIntEquals (test, 0, status);
#endif

	status = engine.base.generate_derived_key_pair (&engine.base, ECC521_PRIVKEY,
		ECC521_PRIVKEY_LEN, NULL, &pub_key);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC521_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC521_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SHA512_TEST_HASH),
		MOCK_ARG (SHA512_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH,
		ECC521_SIGNATURE_TEST, ECC521_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);
#else
	CuAssertIntEquals (test, ECC_ENGINE_UNSUPPORTED_KEY_LENGTH, status);
#endif

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_public_key_generate_derived_key_pair_and_verify_bad_sig (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, ECC_HW_ECDSA_BAD_SIGNATURE,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC_SIGNATURE_BAD_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SIG_HASH_TEST),
		MOCK_ARG (SIG_HASH_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_BAD, ECC_SIG_BAD_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_private_key_generate_derived_key_pair_and_sign (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t out[ECC_TESTING_ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_sign, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_PTR (SIG_HASH_TEST), MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR (NULL),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 5, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (ECC_SIGNATURE_TEST_STRUCT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	// The output is deterministic for this implementation.
	CuAssertIntEquals (test, ECC_SIG_TEST_LEN, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_public_key_generate_derived_key_pair_and_sign (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC_TESTING_ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.sign (&engine.base, (struct ecc_private_key*) &pub_key, SIG_HASH_TEST,
		SIG_HASH_LEN, out, sizeof (out));
	CuAssertIntEquals (test, ECC_ENGINE_NOT_PRIVATE_KEY, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_generate_derived_key_pair_and_sign_and_verify (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_TESTING_ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_sign, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_PTR (SIG_HASH_TEST), MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR (NULL),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 5, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (ECC_SIGNATURE_TEST_STRUCT), -1);

	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	// The output is deterministic for this implementation.
	CuAssertIntEquals (test, ECC_SIG_TEST_LEN, out_len);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SIG_HASH_TEST),
		MOCK_ARG (SIG_HASH_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_generate_derived_key_pair_and_sign_and_verify_p384 (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	int out_len;
	uint8_t out[ECC_TESTING_ECC384_DSA_MAX_LENGTH * 2];
#endif

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PRIVKEY, ECC384_PRIVKEY_LEN), MOCK_ARG (ECC384_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC384_PUBKEY_POINT, sizeof (ECC384_PUBKEY_POINT),
		-1);

	CuAssertIntEquals (test, 0, status);
#endif

	status = engine.base.generate_derived_key_pair (&engine.base, ECC384_PRIVKEY,
		ECC384_PRIVKEY_LEN, &priv_key, &pub_key);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_sign, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PRIVKEY, ECC384_PRIVKEY_LEN), MOCK_ARG (ECC384_PRIVKEY_LEN),
		MOCK_ARG_PTR (SHA384_TEST_HASH), MOCK_ARG (SHA384_HASH_LENGTH), MOCK_ARG_PTR (NULL),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 5, &ECC384_SIGNATURE_TEST_STRUCT,
		sizeof (ECC384_SIGNATURE_TEST_STRUCT), -1);

	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.sign (&engine.base, &priv_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH, out,
		sizeof (out));
	// The output is deterministic for this implementation.
	CuAssertIntEquals (test, ECC384_SIG_TEST_LEN, out_len);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC384_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC384_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SHA384_TEST_HASH),
		MOCK_ARG (SHA384_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH, out,
		out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
#else
	CuAssertIntEquals (test, ECC_ENGINE_UNSUPPORTED_KEY_LENGTH, status);
#endif

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_generate_derived_key_pair_and_sign_and_verify_p521 (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	int out_len;
	uint8_t out[ECC_TESTING_ECC521_DSA_MAX_LENGTH * 2];
#endif

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY, ECC521_PRIVKEY_LEN), MOCK_ARG (ECC521_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC521_PUBKEY_POINT, sizeof (ECC521_PUBKEY_POINT),
		-1);

	CuAssertIntEquals (test, 0, status);
#endif

	status = engine.base.generate_derived_key_pair (&engine.base, ECC521_PRIVKEY,
		ECC521_PRIVKEY_LEN, &priv_key, &pub_key);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_sign, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY, ECC521_PRIVKEY_LEN), MOCK_ARG (ECC521_PRIVKEY_LEN),
		MOCK_ARG_PTR (SHA512_TEST_HASH), MOCK_ARG (SHA512_HASH_LENGTH), MOCK_ARG_PTR (NULL),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 5, &ECC521_SIGNATURE_TEST_STRUCT,
		sizeof (ECC521_SIGNATURE_TEST_STRUCT), -1);

	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.sign (&engine.base, &priv_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH, out,
		sizeof (out));
	// The output is deterministic for this implementation.
	CuAssertIntEquals (test, ECC521_SIG_TEST_LEN, out_len);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC521_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC521_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SHA512_TEST_HASH),
		MOCK_ARG (SHA512_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH, out,
		out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
#else
	CuAssertIntEquals (test, ECC_ENGINE_UNSUPPORTED_KEY_LENGTH, status);
#endif

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_generate_derived_key_pair_and_sign_with_public_key (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC_TESTING_ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.sign (&engine.base, (struct ecc_private_key*) &pub_key, SIG_HASH_TEST,
		SIG_HASH_LEN, out, sizeof (out));
	CuAssertIntEquals (test, ECC_ENGINE_NOT_PRIVATE_KEY, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_generate_derived_key_pair_no_keys (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_generate_derived_key_pair_null (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (NULL, ECC_PRIVKEY, ECC_PRIVKEY_LEN,	&priv_key,
		&pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.generate_derived_key_pair (&engine.base, NULL, ECC_PRIVKEY_LEN, &priv_key,
		&pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, 0, &priv_key,
		&pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_generate_derived_key_pair_unsupported_key_length (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, 16, &priv_key,
		&pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_UNSUPPORTED_KEY_LENGTH, status);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_public_key_generate_key_pair (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.generate_ecc_key_pair, &hw, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 1, ECC_PRIVKEY2, ECC_PRIVKEY2_LEN, -1);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY2_POINT, sizeof (ECC_PUBKEY2_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_private_key_generate_key_pair_and_sign (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t out[ECC_TESTING_ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.generate_ecc_key_pair, &hw, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 1, ECC_PRIVKEY2, ECC_PRIVKEY2_LEN, -1);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY2_POINT, sizeof (ECC_PUBKEY2_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, &priv_key, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_sign, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY2, ECC_PRIVKEY2_LEN), MOCK_ARG (ECC_PRIVKEY2_LEN),
		MOCK_ARG_PTR (SIG_HASH_TEST), MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR (NULL),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 5, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (ECC_SIGNATURE_TEST_STRUCT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	// The output is deterministic for this implementation.
	CuAssertIntEquals (test, ECC_SIG_TEST_LEN, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_public_key_generate_key_pair_and_sign (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC_TESTING_ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.generate_ecc_key_pair, &hw, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 1, ECC_PRIVKEY2, ECC_PRIVKEY2_LEN, -1);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY2_POINT, sizeof (ECC_PUBKEY2_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.sign (&engine.base, (struct ecc_private_key*) &pub_key, SIG_HASH_TEST,
		SIG_HASH_LEN, out, sizeof (out));
	CuAssertIntEquals (test, ECC_ENGINE_NOT_PRIVATE_KEY, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_generate_key_pair_and_sign_and_verify (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_TESTING_ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.generate_ecc_key_pair, &hw, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 1, ECC_PRIVKEY, ECC_PRIVKEY_LEN, -1);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_sign, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_PTR (SIG_HASH_TEST), MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR (NULL),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 5, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (ECC_SIGNATURE_TEST_STRUCT), -1);

	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	// The output is deterministic for this implementation.
	CuAssertIntEquals (test, ECC_SIG_TEST_LEN, out_len);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SIG_HASH_TEST),
		MOCK_ARG (SIG_HASH_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_generate_key_pair_and_sign_and_verify_p384 (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	int out_len;
	uint8_t out[ECC_TESTING_ECC384_DSA_MAX_LENGTH * 2];
#endif

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	status = mock_expect (&hw.mock, hw.base.generate_ecc_key_pair, &hw, 0,
		MOCK_ARG (ECC_KEY_LENGTH_384), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 1, ECC384_PRIVKEY, ECC384_PRIVKEY_LEN, -1);
	status |= mock_expect_output (&hw.mock, 2, &ECC384_PUBKEY_POINT, sizeof (ECC384_PUBKEY_POINT),
		-1);

	CuAssertIntEquals (test, 0, status);
#endif

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_384, &priv_key, &pub_key);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_sign, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PRIVKEY, ECC384_PRIVKEY_LEN), MOCK_ARG (ECC384_PRIVKEY_LEN),
		MOCK_ARG_PTR (SHA384_TEST_HASH), MOCK_ARG (SHA384_HASH_LENGTH), MOCK_ARG_PTR (NULL),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 5, &ECC384_SIGNATURE_TEST_STRUCT,
		sizeof (ECC384_SIGNATURE_TEST_STRUCT), -1);

	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.sign (&engine.base, &priv_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH, out,
		sizeof (out));
	// The output is deterministic for this implementation.
	CuAssertIntEquals (test, ECC384_SIG_TEST_LEN, out_len);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC384_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC384_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SHA384_TEST_HASH),
		MOCK_ARG (SHA384_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH, out,
		out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
#else
	CuAssertIntEquals (test, ECC_ENGINE_UNSUPPORTED_KEY_LENGTH, status);
#endif

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_generate_key_pair_and_sign_and_verify_p521 (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	int out_len;
	uint8_t out[ECC_TESTING_ECC521_DSA_MAX_LENGTH * 2];
#endif

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	status = mock_expect (&hw.mock, hw.base.generate_ecc_key_pair, &hw, 0,
		MOCK_ARG (ECC_KEY_LENGTH_521), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 1, ECC521_PRIVKEY, ECC521_PRIVKEY_LEN, -1);
	status |= mock_expect_output (&hw.mock, 2, &ECC521_PUBKEY_POINT, sizeof (ECC521_PUBKEY_POINT),
		-1);

	CuAssertIntEquals (test, 0, status);
#endif

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_521, &priv_key, &pub_key);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_sign, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY, ECC521_PRIVKEY_LEN), MOCK_ARG (ECC521_PRIVKEY_LEN),
		MOCK_ARG_PTR (SHA512_TEST_HASH), MOCK_ARG (SHA512_HASH_LENGTH), MOCK_ARG_PTR (NULL),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 5, &ECC521_SIGNATURE_TEST_STRUCT,
		sizeof (ECC521_SIGNATURE_TEST_STRUCT), -1);

	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.sign (&engine.base, &priv_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH, out,
		sizeof (out));
	// The output is deterministic for this implementation.
	CuAssertIntEquals (test, ECC521_SIG_TEST_LEN, out_len);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC521_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC521_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SHA512_TEST_HASH),
		MOCK_ARG (SHA512_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH, out,
		out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
#else
	CuAssertIntEquals (test, ECC_ENGINE_UNSUPPORTED_KEY_LENGTH, status);
#endif

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_generate_key_pair_and_sign_with_public_key (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC_TESTING_ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.generate_ecc_key_pair, &hw, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 1, ECC_PRIVKEY2, ECC_PRIVKEY2_LEN, -1);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY2_POINT, sizeof (ECC_PUBKEY2_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.sign (&engine.base, (struct ecc_private_key*) &pub_key, SIG_HASH_TEST,
		SIG_HASH_LEN, out, sizeof (out));
	CuAssertIntEquals (test, ECC_ENGINE_NOT_PRIVATE_KEY, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_generate_key_pair_no_keys (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.generate_ecc_key_pair, &hw, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 1, ECC_PRIVKEY2, ECC_PRIVKEY2_LEN, -1);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY2_POINT, sizeof (ECC_PUBKEY2_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_generate_key_pair_null (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (NULL, ECC_KEY_LENGTH_256, &priv_key, &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_generate_key_pair_unsupported_key_length (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, 16, &priv_key, &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_UNSUPPORTED_KEY_LENGTH, status);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_sign_null (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC_TESTING_ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.sign (NULL, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out, sizeof (out));
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.sign (&engine.base, NULL, SIG_HASH_TEST, SIG_HASH_LEN, out, sizeof (out));
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.sign (&engine.base, &priv_key, NULL, SIG_HASH_LEN, out, sizeof (out));
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, 0, out, sizeof (out));
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, NULL,
		sizeof (out));
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_sign_small_buffer (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC_TESTING_ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_sign, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_PTR (SIG_HASH_TEST), MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR (NULL),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 5, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (ECC_SIGNATURE_TEST_STRUCT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		ECC_TESTING_ECC256_DSA_MAX_LENGTH - 1);
	CuAssertIntEquals (test, ECC_ENGINE_SIG_BUFFER_TOO_SMALL, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_sign_unknown_hash (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC_TESTING_ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.sign (&engine.base, &priv_key, SHA1_TEST_HASH, SHA1_HASH_LENGTH, out,
		ECC_TESTING_ECC256_DSA_MAX_LENGTH);
	CuAssertIntEquals (test, ECC_ENGINE_UNSUPPORTED_HASH_TYPE, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_verify_null (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (NULL, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN, ECC_SIGNATURE_TEST,
		ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.verify (&engine.base, NULL, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.verify (&engine.base, &pub_key, NULL, SIG_HASH_LEN, ECC_SIGNATURE_TEST,
		ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, 0, ECC_SIGNATURE_TEST,
		ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN, NULL,
		ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, 0);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_verify_corrupt_signature (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t bad_sig[ECC_SIG_TEST_LEN];

	TEST_START;

	memcpy (bad_sig, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	bad_sig[0] ^= 0x55;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, NULL,
		&pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN, bad_sig,
		sizeof (bad_sig));
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_get_signature_max_length (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_signature_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC_TESTING_ECC256_DSA_MAX_LENGTH, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
static void ecc_ecc_hw_test_get_signature_max_length_p384 (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_signature_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC_TESTING_ECC384_DSA_MAX_LENGTH, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
static void ecc_ecc_hw_test_get_signature_max_length_p521 (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_signature_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC_TESTING_ECC521_DSA_MAX_LENGTH, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}
#endif

static void ecc_ecc_hw_test_get_signature_max_length_derived_key (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_signature_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC_TESTING_ECC256_DSA_MAX_LENGTH, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_get_signature_max_length_random_key (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.generate_ecc_key_pair, &hw, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 1, ECC_PRIVKEY2, ECC_PRIVKEY2_LEN, -1);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY2_POINT, sizeof (ECC_PUBKEY2_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, &priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_signature_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC_TESTING_ECC256_DSA_MAX_LENGTH, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_get_signature_max_length_null (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_signature_max_length (NULL, &priv_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.get_signature_max_length (&engine.base, NULL);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_get_shared_secret_max_length (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_shared_secret_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC_KEY_LENGTH_256, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
static void ecc_ecc_hw_test_get_shared_secret_max_length_p384 (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_shared_secret_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC_KEY_LENGTH_384, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
static void ecc_ecc_hw_test_get_shared_secret_max_length_p521 (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_shared_secret_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC_KEY_LENGTH_521, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}
#endif

static void ecc_ecc_hw_test_get_shared_secret_max_length_derived_key (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_shared_secret_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC_KEY_LENGTH_256, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_get_shared_secret_max_length_random_key (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.generate_ecc_key_pair, &hw, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 1, ECC_PRIVKEY2, ECC_PRIVKEY2_LEN, -1);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY2_POINT, sizeof (ECC_PUBKEY2_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, &priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_shared_secret_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC_KEY_LENGTH_256, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_get_shared_secret_max_length_null (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_shared_secret_max_length (NULL, &priv_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.get_shared_secret_max_length (&engine.base, NULL);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_compute_shared_secret (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_DH_SECRET_LEN * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdh_compute, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)), MOCK_ARG_PTR (out), MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&hw.mock, 3, ECC_DH_SECRET, ECC_DH_SECRET_LEN, 4);

	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.compute_shared_secret (&engine.base, &priv_key, &pub_key, out,
		sizeof (out));
	CuAssertIntEquals (test, ECC_DH_SECRET_LEN, out_len);

	status = testing_validate_array (ECC_DH_SECRET, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
static void ecc_ecc_hw_test_compute_shared_secret_p384 (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC384_DH_SECRET_LEN * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PRIVKEY, ECC384_PRIVKEY_LEN), MOCK_ARG (ECC384_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC384_PUBKEY_POINT, sizeof (ECC384_PUBKEY_POINT),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdh_compute, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PRIVKEY, ECC384_PRIVKEY_LEN), MOCK_ARG (ECC384_PRIVKEY_LEN),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC384_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)), MOCK_ARG_PTR (out), MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&hw.mock, 3, ECC384_DH_SECRET, ECC384_DH_SECRET_LEN, 4);

	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.compute_shared_secret (&engine.base, &priv_key, &pub_key, out,
		sizeof (out));
	CuAssertIntEquals (test, ECC384_DH_SECRET_LEN, out_len);

	status = testing_validate_array (ECC384_DH_SECRET, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
static void ecc_ecc_hw_test_compute_shared_secret_p521 (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC521_DH_SECRET_LEN * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY, ECC521_PRIVKEY_LEN), MOCK_ARG (ECC521_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC521_PUBKEY_POINT, sizeof (ECC521_PUBKEY_POINT),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdh_compute, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY, ECC521_PRIVKEY_LEN), MOCK_ARG (ECC521_PRIVKEY_LEN),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC521_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)), MOCK_ARG_PTR (out), MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&hw.mock, 3, ECC521_DH_SECRET, ECC521_DH_SECRET_LEN, 4);

	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.compute_shared_secret (&engine.base, &priv_key, &pub_key, out,
		sizeof (out));
	CuAssertIntEquals (test, ECC521_DH_SECRET_LEN, out_len);

	status = testing_validate_array (ECC521_DH_SECRET, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}
#endif

static void ecc_ecc_hw_test_compute_shared_secret_leading_zero (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_DH_SECRET_LEN * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_LEADING_ZERO_DER,
		ECC_PRIVKEY_LEADING_ZERO_DER_LEN, &priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&pub_key);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdh_compute, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY_LEADING_ZERO, ECC_PRIVKEY_LEADING_ZERO_LEN),
		MOCK_ARG (ECC_PRIVKEY_LEADING_ZERO_LEN),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)), MOCK_ARG_PTR (out), MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&hw.mock, 3, ECC_DH_SECRET_LEADING_ZERO,
		ECC_DH_SECRET_LEADING_ZERO_LEN, 4);

	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.compute_shared_secret (&engine.base, &priv_key, &pub_key, out,
		sizeof (out));
	CuAssertIntEquals (test, ECC_DH_SECRET_LEADING_ZERO_LEN, out_len);

	status = testing_validate_array (ECC_DH_SECRET_LEADING_ZERO, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_compute_shared_secret_derived_key (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_DH_SECRET_LEN * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdh_compute, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)), MOCK_ARG_PTR (out), MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&hw.mock, 3, ECC_DH_SECRET, ECC_DH_SECRET_LEN, 4);

	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.compute_shared_secret (&engine.base, &priv_key, &pub_key, out,
		sizeof (out));
	CuAssertIntEquals (test, ECC_DH_SECRET_LEN, out_len);

	status = testing_validate_array (ECC_DH_SECRET, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_compute_shared_secret_null (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC_DH_SECRET_LEN * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.compute_shared_secret (NULL, &priv_key, &pub_key, out,	sizeof (out));
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.compute_shared_secret (&engine.base, NULL, &pub_key, out, sizeof (out));
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.compute_shared_secret (&engine.base, &priv_key, NULL, out,	sizeof (out));
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.compute_shared_secret (&engine.base, &priv_key, &pub_key, NULL,
		sizeof (out));
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_compute_shared_secret_small_buffer (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_DH_SECRET_LEN * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.compute_shared_secret (&engine.base, &priv_key, &pub_key, out,
		ECC_DH_SECRET_LEN - 1);
	CuAssertIntEquals (test, ECC_ENGINE_SECRET_BUFFER_TOO_SMALL, out_len);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_get_private_key_der (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_private_key_der (&engine.base, &priv_key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	CuAssertIntEquals (test, ECC_PRIVKEY_DER_LEN, length);

	status = testing_validate_array (ECC_PRIVKEY_DER, der, ECC_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
static void ecc_ecc_hw_test_get_private_key_der_p384 (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PRIVKEY, ECC384_PRIVKEY_LEN), MOCK_ARG (ECC384_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC384_PUBKEY_POINT, sizeof (ECC384_PUBKEY_POINT),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_private_key_der (&engine.base, &priv_key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	CuAssertIntEquals (test, ECC384_PRIVKEY_DER_LEN, length);

	status = testing_validate_array (ECC384_PRIVKEY_DER, der, ECC384_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
static void ecc_ecc_hw_test_get_private_key_der_p521 (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY, ECC521_PRIVKEY_LEN), MOCK_ARG (ECC521_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC521_PUBKEY_POINT, sizeof (ECC521_PUBKEY_POINT),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_private_key_der (&engine.base, &priv_key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	CuAssertIntEquals (test, ECC521_PRIVKEY_DER_LEN, length);

	status = testing_validate_array (ECC521_PRIVKEY_DER, der, ECC521_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}
#endif

static void ecc_ecc_hw_test_get_private_key_der_derived_key_pair (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_private_key_der (&engine.base, &priv_key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	CuAssertIntEquals (test, ECC_PRIVKEY_DER_LEN, length);

	status = testing_validate_array (ECC_PRIVKEY_DER, der, ECC_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_get_private_key_der_generated_key_pair (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.generate_ecc_key_pair, &hw, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 1, ECC_PRIVKEY2, ECC_PRIVKEY2_LEN, -1);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY2_POINT, sizeof (ECC_PUBKEY2_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, &priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY2, ECC_PRIVKEY2_LEN), MOCK_ARG (ECC_PRIVKEY2_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY2_POINT, sizeof (ECC_PUBKEY2_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_private_key_der (&engine.base, &priv_key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	/* In this implementation, the key is not random, so we know what the output should be. */
	CuAssertIntEquals (test, ECC_PRIVKEY2_DER_LEN, length);

	status = testing_validate_array (ECC_PRIVKEY2_DER, der, ECC_PRIVKEY2_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_get_private_key_der_null (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t *der;
	size_t length;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	der = (uint8_t*) &status;
	status = engine.base.get_private_key_der (NULL, &priv_key, &der, &length);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, der);

	der = (uint8_t*) &status;
	status = engine.base.get_private_key_der (&engine.base, NULL, &der, &length);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, der);

	status = engine.base.get_private_key_der (&engine.base, &priv_key, NULL, &length);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	der = (uint8_t*) &status;
	status = engine.base.get_private_key_der (&engine.base, &priv_key, &der, NULL);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, der);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_get_private_key_der_public_key_from_private (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t *der = (uint8_t*) &status;
	size_t length;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, NULL,
		&pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_private_key_der (&engine.base, (struct ecc_private_key*) &pub_key,
		&der, &length);
	CuAssertIntEquals (test, ECC_ENGINE_NOT_PRIVATE_KEY, status);
	CuAssertPtrEquals (test, NULL, der);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_get_private_key_der_public_key (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t *der = (uint8_t*) &status;
	size_t length;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_private_key_der (&engine.base, (struct ecc_private_key*) &pub_key,
		&der, &length);
	CuAssertIntEquals (test, ECC_ENGINE_NOT_PRIVATE_KEY, status);
	CuAssertPtrEquals (test, NULL, der);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_get_public_key_der (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, NULL,
		&pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_der (&engine.base, &pub_key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	CuAssertIntEquals (test, ECC_PUBKEY_DER_LEN, length);

	status = testing_validate_array (ECC_PUBKEY_DER, der, ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
static void ecc_ecc_hw_test_get_public_key_der_p384 (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PRIVKEY, ECC384_PRIVKEY_LEN), MOCK_ARG (ECC384_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC384_PUBKEY_POINT, sizeof (ECC384_PUBKEY_POINT),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_der (&engine.base, &pub_key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	CuAssertIntEquals (test, ECC384_PUBKEY_DER_LEN, length);

	status = testing_validate_array (ECC384_PUBKEY_DER, der, ECC384_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
static void ecc_ecc_hw_test_get_public_key_der_p521 (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY, ECC521_PRIVKEY_LEN), MOCK_ARG (ECC521_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC521_PUBKEY_POINT, sizeof (ECC521_PUBKEY_POINT),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN,
		NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_der (&engine.base, &pub_key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	CuAssertIntEquals (test, ECC521_PUBKEY_DER_LEN, length);

	status = testing_validate_array (ECC521_PUBKEY_DER, der, ECC521_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}
#endif

static void ecc_ecc_hw_test_get_public_key_der_derived_key_pair (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_der (&engine.base, &pub_key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	CuAssertIntEquals (test, ECC_PUBKEY_DER_LEN, length);

	status = testing_validate_array (ECC_PUBKEY_DER, der, ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_get_public_key_der_generated_key_pair (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.generate_ecc_key_pair, &hw, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 1, ECC_PRIVKEY2, ECC_PRIVKEY2_LEN, -1);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY2_POINT, sizeof (ECC_PUBKEY2_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_der (&engine.base, &pub_key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	CuAssertIntEquals (test, ECC_PUBKEY2_DER_LEN, length);

	/* In this implementation, the key is not random, so we know what the output should be. */
	status = testing_validate_array (ECC_PUBKEY2_DER, der, ECC_PUBKEY2_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_get_public_key_der_null (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t *der;
	size_t length;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, NULL,
		&pub_key);
	CuAssertIntEquals (test, 0, status);

	der = (uint8_t*) &status;
	status = engine.base.get_public_key_der (NULL, &pub_key, &der, &length);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, der);

	der = (uint8_t*) &status;
	status = engine.base.get_public_key_der (&engine.base, NULL, &der, &length);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, der);

	status = engine.base.get_public_key_der (&engine.base, &pub_key, NULL, &length);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	der = (uint8_t*) &status;
	status = engine.base.get_public_key_der (&engine.base, &pub_key, &der, NULL);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, der);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_get_public_key_der_private_key (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t *der = (uint8_t*) &status;
	size_t length;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_der (&engine.base, (struct ecc_public_key*) &priv_key, &der,
		&length);
	CuAssertIntEquals (test, ECC_ENGINE_NOT_PUBLIC_KEY, status);
	CuAssertPtrEquals (test, NULL, der);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_static_init (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine = ecc_ecc_hw_static_init (&hw.base, NULL);

	TEST_START;

	CuAssertPtrNotNull (test, engine.base.init_key_pair);
	CuAssertPtrNotNull (test, engine.base.init_public_key);
	CuAssertPtrNotNull (test, engine.base.generate_derived_key_pair);
	CuAssertPtrNotNull (test, engine.base.generate_key_pair);
	CuAssertPtrNotNull (test, engine.base.release_key_pair);
	CuAssertPtrNotNull (test, engine.base.get_signature_max_length);
	CuAssertPtrNotNull (test, engine.base.get_private_key_der);
	CuAssertPtrNotNull (test, engine.base.get_public_key_der);
	CuAssertPtrNotNull (test, engine.base.sign);
	CuAssertPtrNotNull (test, engine.base.verify);
	CuAssertPtrNotNull (test, engine.base.get_shared_secret_max_length);
	CuAssertPtrNotNull (test, engine.base.compute_shared_secret);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_init_key_pair_and_sign_and_verify_static_init (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine = ecc_ecc_hw_static_init (&hw.base, NULL);
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_TESTING_ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_sign, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_PTR (SIG_HASH_TEST), MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR (NULL),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 5, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (ECC_SIGNATURE_TEST_STRUCT), -1);

	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	CuAssertTrue (test, !ROT_IS_ERROR (out_len));

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SIG_HASH_TEST),
		MOCK_ARG (SIG_HASH_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
	CuAssertPtrEquals (test, NULL, priv_key.context);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_init_public_key_and_verify_static_init (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine = ecc_ecc_hw_static_init (&hw.base, NULL);
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SIG_HASH_TEST),
		MOCK_ARG (SIG_HASH_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_generate_derived_key_pair_and_sign_and_verify_static_init (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine = ecc_ecc_hw_static_init (&hw.base, NULL);
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_TESTING_ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_sign, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_PTR (SIG_HASH_TEST), MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR (NULL),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 5, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (ECC_SIGNATURE_TEST_STRUCT), -1);

	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	CuAssertTrue (test, !ROT_IS_ERROR (out_len));

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SIG_HASH_TEST),
		MOCK_ARG (SIG_HASH_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_generate_key_pair_and_sign_and_verify_static_init (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine = ecc_ecc_hw_static_init (&hw.base, NULL);
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_TESTING_ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.generate_ecc_key_pair, &hw, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 1, ECC_PRIVKEY, ECC_PRIVKEY_LEN, -1);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_sign, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_PTR (SIG_HASH_TEST), MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR (NULL),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 5, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (ECC_SIGNATURE_TEST_STRUCT), -1);

	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	CuAssertTrue (test, !ROT_IS_ERROR (out_len));

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SIG_HASH_TEST),
		MOCK_ARG (SIG_HASH_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_get_signature_max_length_static_init (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine = ecc_ecc_hw_static_init (&hw.base, NULL);
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_signature_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC_TESTING_ECC256_DSA_MAX_LENGTH, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_get_shared_secret_max_length_static_init (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine = ecc_ecc_hw_static_init (&hw.base, NULL);
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_shared_secret_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC_KEY_LENGTH_256, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_compute_shared_secret_static_init (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine = ecc_ecc_hw_static_init (&hw.base, NULL);
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_DH_SECRET_LEN * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdh_compute, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)), MOCK_ARG_PTR (out), MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&hw.mock, 3, ECC_DH_SECRET, ECC_DH_SECRET_LEN, 4);

	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.compute_shared_secret (&engine.base, &priv_key, &pub_key, out,
		sizeof (out));
	CuAssertIntEquals (test, ECC_DH_SECRET_LEN, out_len);

	status = testing_validate_array (ECC_DH_SECRET, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_get_private_key_der_static_init (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine = ecc_ecc_hw_static_init (&hw.base, NULL);
	struct ecc_private_key priv_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_private_key_der (&engine.base, &priv_key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	CuAssertIntEquals (test, ECC_PRIVKEY_DER_LEN, length);

	status = testing_validate_array (ECC_PRIVKEY_DER, der, ECC_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_get_public_key_der_static_init (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine = ecc_ecc_hw_static_init (&hw.base, NULL);
	struct ecc_public_key pub_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, NULL,
		&pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_der (&engine.base, &pub_key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	CuAssertIntEquals (test, ECC_PUBKEY_DER_LEN, length);

	status = testing_validate_array (ECC_PUBKEY_DER, der, ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_init_key_pair_hw_public_key_error (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, ECC_HW_ECC_PUBLIC_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, ECC_HW_ECC_PUBLIC_FAILED, status);
	CuAssertPtrEquals (test, NULL, priv_key.context);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_generate_key_pair_hw_error (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.generate_ecc_key_pair, &hw, ECC_HW_ECC_GENERATE_FAILED,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, &priv_key, &pub_key);
	CuAssertIntEquals (test, ECC_HW_ECC_GENERATE_FAILED, status);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_sign_with_rng (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct rng_engine_mock rng;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t out[ECC_TESTING_ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_sign, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_PTR (SIG_HASH_TEST), MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR (&rng),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 5, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (ECC_SIGNATURE_TEST_STRUCT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	// The output is deterministic for this implementation.
	CuAssertIntEquals (test, ECC_SIG_TEST_LEN, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);
	CuAssertPtrEquals (test, NULL, priv_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	status |= rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_sign_with_rng_static_init (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct rng_engine_mock rng;
	struct ecc_engine_ecc_hw engine = ecc_ecc_hw_static_init (&hw.base, &rng.base);
	struct ecc_private_key priv_key;
	int status;
	uint8_t out[ECC_TESTING_ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_sign, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_PTR (SIG_HASH_TEST), MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR (&rng),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 5, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (ECC_SIGNATURE_TEST_STRUCT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	// The output is deterministic for this implementation.
	CuAssertIntEquals (test, ECC_SIG_TEST_LEN, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);
	CuAssertPtrEquals (test, NULL, priv_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	status |= rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_sign_hw_error (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t out[ECC_TESTING_ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_sign, &hw, ECC_HW_ECDSA_SIGN_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_PTR (SIG_HASH_TEST), MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR (NULL),
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	CuAssertIntEquals (test, ECC_HW_ECDSA_SIGN_FAILED, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);
	CuAssertPtrEquals (test, NULL, priv_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_verify_hw_error (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, NULL,
		&pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdsa_verify, &hw, ECC_HW_ECDSA_VERIFY_FAILED,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)), MOCK_ARG_PTR (SIG_HASH_TEST),
		MOCK_ARG (SIG_HASH_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, ECC_HW_ECDSA_VERIFY_FAILED, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_compute_shared_secret_hw_error (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_DH_SECRET_LEN * 2];

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT), -1);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.ecdh_compute, &hw, ECC_HW_ECDH_COMPUTE_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)), MOCK_ARG_PTR (out), MOCK_ARG (sizeof (out)));

	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.compute_shared_secret (&engine.base, &priv_key, &pub_key, out,
		sizeof (out));
	CuAssertIntEquals (test, ECC_HW_ECDH_COMPUTE_FAILED, out_len);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}

static void ecc_ecc_hw_test_get_private_key_der_hw_error (CuTest *test)
{
	struct ecc_hw_mock hw;
	struct ecc_engine_ecc_hw engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t *der = (uint8_t*) &status;
	size_t length;

	TEST_START;

	status = ecc_hw_mock_init (&hw);
	CuAssertIntEquals (test, 0, status);

	status = ecc_ecc_hw_init (&engine, &hw.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hw.mock, hw.base.get_ecc_public_key, &hw, ECC_HW_ECC_PUBLIC_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_PRIVKEY_LEN),
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_private_key_der (&engine.base, &priv_key, &der, &length);
	CuAssertIntEquals (test, ECC_HW_ECC_PUBLIC_FAILED, status);
	CuAssertPtrEquals (test, NULL, der);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	status = ecc_hw_mock_validate_and_release (&hw);
	CuAssertIntEquals (test, 0, status);

	ecc_ecc_hw_release (&engine);
}


// *INDENT-OFF*
TEST_SUITE_START (ecc_ecc_hw);

TEST (ecc_ecc_hw_test_init);
TEST (ecc_ecc_hw_test_init_null);
TEST (ecc_ecc_hw_test_release_null);
TEST (ecc_ecc_hw_test_public_key_init_key_pair_and_verify);
TEST (ecc_ecc_hw_test_public_key_init_key_pair_and_verify_no_pubkey);
TEST (ecc_ecc_hw_test_public_key_init_key_pair_and_verify_extra_buffer);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
TEST (ecc_ecc_hw_test_public_key_init_key_pair_and_verify_p384);
TEST (ecc_ecc_hw_test_public_key_init_key_pair_and_verify_p384_no_pubkey);
TEST (ecc_ecc_hw_test_public_key_init_key_pair_and_verify_p384_extra_buffer);
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
TEST (ecc_ecc_hw_test_public_key_init_key_pair_and_verify_p521);
TEST (ecc_ecc_hw_test_public_key_init_key_pair_and_verify_p521_no_pubkey);
TEST (ecc_ecc_hw_test_public_key_init_key_pair_and_verify_p521_extra_buffer);
#endif
TEST (ecc_ecc_hw_test_public_key_init_key_pair_and_verify_bad_sig);
TEST (ecc_ecc_hw_test_private_key_init_key_pair_and_sign);
TEST (ecc_ecc_hw_test_public_key_init_key_pair_and_sign);
TEST (ecc_ecc_hw_test_init_key_pair_and_sign_and_verify);
TEST (ecc_ecc_hw_test_init_key_pair_and_sign_and_verify_no_pubkey);
TEST (ecc_ecc_hw_test_init_key_pair_and_sign_and_verify_extra_buffer);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
TEST (ecc_ecc_hw_test_init_key_pair_and_sign_and_verify_p384);
TEST (ecc_ecc_hw_test_init_key_pair_and_sign_and_verify_p384_no_pubkey);
TEST (ecc_ecc_hw_test_init_key_pair_and_sign_and_verify_p384_extra_buffer);
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
TEST (ecc_ecc_hw_test_init_key_pair_and_sign_and_verify_p521);
TEST (ecc_ecc_hw_test_init_key_pair_and_sign_and_verify_p521_no_pubkey);
TEST (ecc_ecc_hw_test_init_key_pair_and_sign_and_verify_p521_no_leading_zero);
TEST (ecc_ecc_hw_test_init_key_pair_and_sign_and_verify_p521_extra_buffer);
#endif
TEST (ecc_ecc_hw_test_init_key_pair_and_sign_with_public_key);
TEST (ecc_ecc_hw_test_init_key_pair_no_keys);
TEST (ecc_ecc_hw_test_init_key_pair_null);
TEST (ecc_ecc_hw_test_init_key_pair_with_public_key);
TEST (ecc_ecc_hw_test_init_key_pair_with_rsa_key);
TEST (ecc_ecc_hw_test_init_public_key_and_verify);
TEST (ecc_ecc_hw_test_init_public_key_and_verify_extra_buffer);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
TEST (ecc_ecc_hw_test_init_public_key_and_verify_p384);
TEST (ecc_ecc_hw_test_init_public_key_and_verify_p384_extra_buffer);
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
TEST (ecc_ecc_hw_test_init_public_key_and_verify_p521);
TEST (ecc_ecc_hw_test_init_public_key_and_verify_p521_extra_buffer);
#endif
TEST (ecc_ecc_hw_test_init_public_key_and_verify_bad_sig);
TEST (ecc_ecc_hw_test_init_public_key_null);
TEST (ecc_ecc_hw_test_init_public_key_with_private_key);
TEST (ecc_ecc_hw_test_init_public_key_with_rsa_key);
TEST (ecc_ecc_hw_test_public_key_generate_derived_key_pair_and_verify);
TEST (ecc_ecc_hw_test_public_key_generate_derived_key_pair_and_verify_p384);
TEST (ecc_ecc_hw_test_public_key_generate_derived_key_pair_and_verify_p521);
TEST (ecc_ecc_hw_test_public_key_generate_derived_key_pair_and_verify_bad_sig);
TEST (ecc_ecc_hw_test_private_key_generate_derived_key_pair_and_sign);
TEST (ecc_ecc_hw_test_public_key_generate_derived_key_pair_and_sign);
TEST (ecc_ecc_hw_test_generate_derived_key_pair_and_sign_and_verify);
TEST (ecc_ecc_hw_test_generate_derived_key_pair_and_sign_and_verify_p384);
TEST (ecc_ecc_hw_test_generate_derived_key_pair_and_sign_and_verify_p521);
TEST (ecc_ecc_hw_test_generate_derived_key_pair_and_sign_with_public_key);
TEST (ecc_ecc_hw_test_generate_derived_key_pair_no_keys);
TEST (ecc_ecc_hw_test_generate_derived_key_pair_null);
TEST (ecc_ecc_hw_test_generate_derived_key_pair_unsupported_key_length);
TEST (ecc_ecc_hw_test_public_key_generate_key_pair);
TEST (ecc_ecc_hw_test_private_key_generate_key_pair_and_sign);
TEST (ecc_ecc_hw_test_public_key_generate_key_pair_and_sign);
TEST (ecc_ecc_hw_test_generate_key_pair_and_sign_and_verify);
TEST (ecc_ecc_hw_test_generate_key_pair_and_sign_and_verify_p384);
TEST (ecc_ecc_hw_test_generate_key_pair_and_sign_and_verify_p521);
TEST (ecc_ecc_hw_test_generate_key_pair_and_sign_with_public_key);
TEST (ecc_ecc_hw_test_generate_key_pair_no_keys);
TEST (ecc_ecc_hw_test_generate_key_pair_null);
TEST (ecc_ecc_hw_test_generate_key_pair_unsupported_key_length);
TEST (ecc_ecc_hw_test_sign_null);
TEST (ecc_ecc_hw_test_sign_small_buffer);
TEST (ecc_ecc_hw_test_sign_unknown_hash);
TEST (ecc_ecc_hw_test_verify_null);
TEST (ecc_ecc_hw_test_verify_corrupt_signature);
TEST (ecc_ecc_hw_test_get_signature_max_length);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
TEST (ecc_ecc_hw_test_get_signature_max_length_p384);
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
TEST (ecc_ecc_hw_test_get_signature_max_length_p521);
#endif
TEST (ecc_ecc_hw_test_get_signature_max_length_derived_key);
TEST (ecc_ecc_hw_test_get_signature_max_length_random_key);
TEST (ecc_ecc_hw_test_get_signature_max_length_null);
TEST (ecc_ecc_hw_test_get_shared_secret_max_length);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
TEST (ecc_ecc_hw_test_get_shared_secret_max_length_p384);
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
TEST (ecc_ecc_hw_test_get_shared_secret_max_length_p521);
#endif
TEST (ecc_ecc_hw_test_get_shared_secret_max_length_derived_key);
TEST (ecc_ecc_hw_test_get_shared_secret_max_length_random_key);
TEST (ecc_ecc_hw_test_get_shared_secret_max_length_null);
TEST (ecc_ecc_hw_test_compute_shared_secret);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
TEST (ecc_ecc_hw_test_compute_shared_secret_p384);
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
TEST (ecc_ecc_hw_test_compute_shared_secret_p521);
#endif
TEST (ecc_ecc_hw_test_compute_shared_secret_leading_zero);
TEST (ecc_ecc_hw_test_compute_shared_secret_derived_key);
// Not relevant for this implementation, since it doesn't actually do crypto.
// TEST (ecc_ecc_hw_test_compute_shared_secret_different_keys);
TEST (ecc_ecc_hw_test_compute_shared_secret_null);
TEST (ecc_ecc_hw_test_compute_shared_secret_small_buffer);
TEST (ecc_ecc_hw_test_get_private_key_der);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
TEST (ecc_ecc_hw_test_get_private_key_der_p384);
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
TEST (ecc_ecc_hw_test_get_private_key_der_p521);
#endif
TEST (ecc_ecc_hw_test_get_private_key_der_derived_key_pair);
TEST (ecc_ecc_hw_test_get_private_key_der_generated_key_pair);
TEST (ecc_ecc_hw_test_get_private_key_der_null);
TEST (ecc_ecc_hw_test_get_private_key_der_public_key_from_private);
TEST (ecc_ecc_hw_test_get_private_key_der_public_key);
TEST (ecc_ecc_hw_test_get_public_key_der);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
TEST (ecc_ecc_hw_test_get_public_key_der_p384);
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
TEST (ecc_ecc_hw_test_get_public_key_der_p521);
#endif
TEST (ecc_ecc_hw_test_get_public_key_der_derived_key_pair);
TEST (ecc_ecc_hw_test_get_public_key_der_generated_key_pair);
TEST (ecc_ecc_hw_test_get_public_key_der_null);
TEST (ecc_ecc_hw_test_get_public_key_der_private_key);

/* Tests for static initialization. */
TEST (ecc_ecc_hw_test_static_init);
TEST (ecc_ecc_hw_test_init_key_pair_and_sign_and_verify_static_init);
TEST (ecc_ecc_hw_test_init_public_key_and_verify_static_init);
TEST (ecc_ecc_hw_test_generate_derived_key_pair_and_sign_and_verify_static_init);
TEST (ecc_ecc_hw_test_generate_key_pair_and_sign_and_verify_static_init);
TEST (ecc_ecc_hw_test_get_signature_max_length_static_init);
TEST (ecc_ecc_hw_test_get_shared_secret_max_length_static_init);
TEST (ecc_ecc_hw_test_compute_shared_secret_static_init);
TEST (ecc_ecc_hw_test_get_private_key_der_static_init);
TEST (ecc_ecc_hw_test_get_public_key_der_static_init);

/* Additional tests specific to this implementation. */
TEST (ecc_ecc_hw_test_init_key_pair_hw_public_key_error);
TEST (ecc_ecc_hw_test_generate_key_pair_hw_error);
TEST (ecc_ecc_hw_test_sign_with_rng);
TEST (ecc_ecc_hw_test_sign_with_rng_static_init);
TEST (ecc_ecc_hw_test_sign_hw_error);
TEST (ecc_ecc_hw_test_verify_hw_error);
TEST (ecc_ecc_hw_test_compute_shared_secret_hw_error);
TEST (ecc_ecc_hw_test_get_private_key_der_hw_error);

TEST_SUITE_END;
// *INDENT-ON*
