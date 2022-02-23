// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "platform.h"
#include "testing.h"
#include "cmd_interface/session_manager_ecc.h"
#include "cmd_interface/cerberus_protocol_optional_commands.h"
#include "testing/mock/crypto/aes_mock.h"
#include "testing/mock/crypto/ecc_mock.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/crypto/rng_mock.h"
#include "testing/mock/crypto/x509_mock.h"
#include "testing/mock/keystore/keystore_mock.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/riot/riot_core_testing.h"


TEST_SUITE_LABEL ("session_manager_ecc");


static struct riot_keys keys = {
	.devid_cert = RIOT_CORE_DEVID_CERT,
	.devid_cert_length = 0,
	.devid_csr = NULL,
	.devid_csr_length = 0,
	.alias_key = RIOT_CORE_ALIAS_KEY,
	.alias_key_length = 0,
	.alias_cert = RIOT_CORE_ALIAS_CERT,
	.alias_cert_length = 0
};

static const uint8_t SHARED_SECRET[] = {
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
};

static const uint8_t SESSION_AES_IV[] = {
	0xaa,0xee,0xff,0x11,0x44,0xdd,0x77,0xcc,0x22,0xaa,0xdd,0xff
};

static const uint8_t SESSION_AES_GCM_TAG[] = {
	0x77,0x0e,0x72,0x2a,0x01,0xf8,0xfb,0xf6,0x26,0x1d,0x78,0xec,0x83,0xff,0xcf,0x4c
};

static const uint8_t PAIRING_EIDS[] = {
	0x10,0x11
};

static const uint8_t HMAC_KEY[] = {
	0xf1,0x3b,0x43,0x16,0xd5,0xc5,0xc6,0x10,0xad,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x37,
	0x0e,0x9a,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
};

/**
 * Dependencies for testing the system command interface.
 */
struct session_manager_ecc_testing {
	struct session_manager_ecc session;				/**< Session manager instance. */
	struct aes_engine_mock aes;						/**< AES engine mock. */
	struct ecc_engine_mock ecc;						/**< ECC engine mock. */
	struct hash_engine_mock hash; 					/**< Hash engine mock. */
	struct rng_engine_mock rng; 					/**< RNG engine mock. */
	struct keystore_mock riot_keystore;				/**< RIoT keystore. */
	struct riot_key_manager riot; 					/**< RIoT key manager. */
	struct x509_engine_mock x509;					/**< RIoT x509 engine mock. */
	struct keystore_mock keys_keystore;				/**< Pairing keys keystore. */
};


/**
 * Helper function to setup a session manager for testing.
 *
 * @param test The test framework.
 * @param cmd The instance to use for testing.
 */
static void setup_session_manager_ecc_test (CuTest *test, struct session_manager_ecc_testing *cmd)
{
	uint8_t *dev_id_der = NULL;
	int status;

	status = aes_mock_init (&cmd->aes);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&cmd->ecc);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&cmd->hash);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&cmd->rng);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&cmd->x509);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&cmd->keys_keystore);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&cmd->riot_keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd->riot_keystore.mock, cmd->riot_keystore.base.load_key,
		&cmd->riot_keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd->riot_keystore.mock, 1, &dev_id_der, sizeof (dev_id_der),
		-1);
	CuAssertIntEquals (test, 0, status);

	keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;
	keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
	keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&cmd->riot, &cmd->riot_keystore.base, &keys,
		&cmd->x509.base);
	CuAssertIntEquals (test, 0, status);

	status = session_manager_ecc_init (&cmd->session, &cmd->aes.base, &cmd->ecc.base,
		&cmd->hash.base, &cmd->rng.base, &cmd->riot, NULL, 3, PAIRING_EIDS, 2,
		&cmd->keys_keystore.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper function to release session manager utilized for testing.
 *
 * @param test The test framework.
 * @param cmd The instance to use to release.
 */
static void release_session_manager_ecc_test (CuTest *test, struct session_manager_ecc_testing *cmd)
{
	int status;

	status = aes_mock_validate_and_release (&cmd->aes);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&cmd->ecc);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&cmd->hash);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&cmd->rng);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&cmd->x509);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&cmd->keys_keystore);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&cmd->riot_keystore);
	CuAssertIntEquals (test, 0, status);

	riot_key_manager_release (&cmd->riot);

	session_manager_ecc_release (&cmd->session);
}

static void session_manager_ecc_establish_session (CuTest *test,
	struct session_manager_ecc_testing *cmd, uint8_t eid)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	struct cerberus_protocol_key_exchange_type_0 *rq_ptr =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t session_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t digest[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0x0e,0x9a,0x37,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,
		0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0xd5,0xc5,0xc6
	};
	uint8_t hmac[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0xad,0xd5,0xc5,0xc6,0x9a,0x37,0xff,0x3e,0x75,
		0x0e,0x73,0xc5,0x54,0x10,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t *ecc_cerberus_key;
	uint32_t i_1 = platform_htonl (1);
	uint8_t separator = 0;
	uint32_t L = platform_htonl (256);
	int status;

	rq.data = data;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	rq.source_eid = eid;
	rq.length = cerberus_protocol_key_exchange_type_0_length (ECC_PUBKEY_DER_LEN);

	rq_ptr->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;
	rq_ptr->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (((uint8_t*) rq_ptr) + sizeof (struct cerberus_protocol_key_exchange_type_0),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);

	ecc_cerberus_key = platform_malloc (ECC_PUBKEY2_DER_LEN);
	CuAssertPtrNotNull (test, ecc_cerberus_key);

	memcpy (ecc_cerberus_key, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN);

	status = cmd->session.base.add_session (&cmd->session.base, eid, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd->ecc.mock, cmd->ecc.base.init_public_key, &cmd->ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd->ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd->ecc.mock, cmd->ecc.base.generate_key_pair, &cmd->ecc, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd->ecc.mock, 1, 1);
	status |= mock_expect_save_arg (&cmd->ecc.mock, 2, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd->ecc.mock, cmd->ecc.base.get_public_key_der, &cmd->ecc, 0,
		MOCK_ARG_SAVED_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd->ecc.mock, 1, &ecc_cerberus_key, sizeof (ecc_cerberus_key),
		-1);
	status |= mock_expect_output (&cmd->ecc.mock, 2, &ECC_PUBKEY2_DER_LEN,
		sizeof (ECC_PUBKEY2_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd->hash.mock, cmd->hash.base.start_sha256, &cmd->hash, 0);
	status |= mock_expect (&cmd->hash.mock, cmd->hash.base.update, &cmd->hash, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN));
	status |= mock_expect (&cmd->hash.mock, cmd->hash.base.update, &cmd->hash, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN),
		MOCK_ARG (ECC_PUBKEY2_DER_LEN));
	status |= mock_expect (&cmd->hash.mock, cmd->hash.base.finish, &cmd->hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&cmd->hash.mock, 0, digest, sizeof (digest), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd->ecc.mock, cmd->ecc.base.init_key_pair, &cmd->ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd->ecc.mock, 2, 3);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd->ecc.mock, cmd->ecc.base.get_signature_max_length, &cmd->ecc, 91,
		MOCK_ARG_SAVED_ARG (3));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd->ecc.mock, cmd->ecc.base.sign, &cmd->ecc, ECC_SIG_TEST_LEN,
		MOCK_ARG_SAVED_ARG (3), MOCK_ARG_PTR_CONTAINS_TMP (digest, sizeof (digest)),
		MOCK_ARG (sizeof (digest)), MOCK_ARG_NOT_NULL, MOCK_ARG (rq.max_response -
		sizeof (struct cerberus_protocol_key_exchange_response_type_0) - ECC_PUBKEY2_DER_LEN -
		sizeof (uint16_t)));
	status |= mock_expect_output (&cmd->ecc.mock, 3, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd->ecc.mock, cmd->ecc.base.get_shared_secret_max_length, &cmd->ecc, 64,
		MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd->ecc.mock, cmd->ecc.base.compute_shared_secret, &cmd->ecc, 64,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&cmd->ecc.mock, 2, SHARED_SECRET, sizeof (SHARED_SECRET), 3);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd->hash, SHARED_SECRET, sizeof (SHARED_SECRET));
	status |= mock_expect (&cmd->hash.mock, cmd->hash.base.update, &cmd->hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&i_1, sizeof (i_1)), MOCK_ARG (sizeof (i_1)));
	status |= mock_expect (&cmd->hash.mock, cmd->hash.base.update, &cmd->hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&nonce1, sizeof (nonce1)), MOCK_ARG (sizeof (nonce1)));
	status |= mock_expect (&cmd->hash.mock, cmd->hash.base.update, &cmd->hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&cmd->hash.mock, cmd->hash.base.update, &cmd->hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&nonce2, sizeof (nonce2)), MOCK_ARG (sizeof (nonce2)));
	status |= mock_expect (&cmd->hash.mock, cmd->hash.base.update, &cmd->hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&L, sizeof (L)), MOCK_ARG (sizeof (L)));
	status |= hash_mock_expect_hmac_finish (&cmd->hash, SHARED_SECRET, sizeof (SHARED_SECRET),
		NULL, SHA256_HASH_LENGTH, session_key, sizeof (session_key));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd->hash, SHARED_SECRET, sizeof (SHARED_SECRET));
	status |= mock_expect (&cmd->hash.mock, cmd->hash.base.update, &cmd->hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&i_1, sizeof (i_1)), MOCK_ARG (sizeof (i_1)));
	status |= mock_expect (&cmd->hash.mock, cmd->hash.base.update, &cmd->hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&nonce2, sizeof (nonce2)), MOCK_ARG (sizeof (nonce2)));
	status |= mock_expect (&cmd->hash.mock, cmd->hash.base.update, &cmd->hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&cmd->hash.mock, cmd->hash.base.update, &cmd->hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&nonce1, sizeof (nonce1)), MOCK_ARG (sizeof (nonce1)));
	status |= mock_expect (&cmd->hash.mock, cmd->hash.base.update, &cmd->hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&L, sizeof (L)), MOCK_ARG (sizeof (L)));
	status |= hash_mock_expect_hmac_finish (&cmd->hash, SHARED_SECRET, sizeof (SHARED_SECRET),
		NULL, SHA256_HASH_LENGTH, HMAC_KEY, sizeof (HMAC_KEY));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd->hash, HMAC_KEY, sizeof (HMAC_KEY));
	status |= mock_expect (&cmd->hash.mock, cmd->hash.base.update, &cmd->hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN));
	status |= hash_mock_expect_hmac_finish (&cmd->hash, HMAC_KEY, sizeof (HMAC_KEY), NULL,
		rq.max_response - sizeof (struct cerberus_protocol_key_exchange_response_type_0) -
		ECC_PUBKEY2_DER_LEN - sizeof (uint16_t)*2 - ECC_SIG_TEST_LEN, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd->ecc.mock, cmd->ecc.base.release_key_pair, &cmd->ecc, 0,
		MOCK_ARG_SAVED_ARG (3), MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd->ecc.mock, cmd->ecc.base.release_key_pair, &cmd->ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd->ecc.mock, cmd->ecc.base.release_key_pair, &cmd->ecc, 0,
		MOCK_ARG (NULL), MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = cmd->session.base.establish_session (&cmd->session.base, &rq);
	CuAssertIntEquals (test, 0, status);
}

/*******************
 * Test cases
 *******************/

static void session_manager_ecc_test_init (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t *dev_id_der = NULL;
	int status;

	TEST_START;

	status = aes_mock_init (&cmd.aes);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&cmd.ecc);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&cmd.hash);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&cmd.rng);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&cmd.x509);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&cmd.keys_keystore);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&cmd.riot_keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.riot_keystore.mock, cmd.riot_keystore.base.load_key,
		&cmd.riot_keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.riot_keystore.mock, 1, &dev_id_der, sizeof (dev_id_der), -1);
	CuAssertIntEquals (test, 0, status);

	keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;
	keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
	keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&cmd.riot, &cmd.riot_keystore.base, &keys,
		&cmd.x509.base);
	CuAssertIntEquals (test, 0, status);

	status = session_manager_ecc_init (&cmd.session, &cmd.aes.base, &cmd.ecc.base, &cmd.hash.base,
		&cmd.rng.base, &cmd.riot, NULL, 1, NULL, 0, &cmd.keys_keystore.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cmd.session.base.add_session);
	CuAssertPtrNotNull (test, cmd.session.base.establish_session);
	CuAssertPtrNotNull (test, cmd.session.base.is_session_established);
	CuAssertPtrNotNull (test, cmd.session.base.get_pairing_state);
	CuAssertPtrNotNull (test, cmd.session.base.decrypt_message);
	CuAssertPtrNotNull (test, cmd.session.base.encrypt_message);
	CuAssertPtrNotNull (test, cmd.session.base.reset_session);
	CuAssertPtrNotNull (test, cmd.session.base.setup_paired_session);
	CuAssertPtrNotNull (test, cmd.session.base.session_sync);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_init_preallocated_table (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	struct session_manager_entry sessions_table[2];
	uint8_t *dev_id_der = NULL;
	int status;

	TEST_START;

	status = aes_mock_init (&cmd.aes);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&cmd.ecc);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&cmd.hash);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&cmd.rng);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&cmd.x509);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&cmd.keys_keystore);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&cmd.riot_keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.riot_keystore.mock, cmd.riot_keystore.base.load_key,
		&cmd.riot_keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.riot_keystore.mock, 1, &dev_id_der, sizeof (dev_id_der), -1);
	CuAssertIntEquals (test, 0, status);

	keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;
	keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
	keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&cmd.riot, &cmd.riot_keystore.base, &keys,
		&cmd.x509.base);
	CuAssertIntEquals (test, 0, status);

	status = session_manager_ecc_init (&cmd.session, &cmd.aes.base,
		&cmd.ecc.base, &cmd.hash.base, &cmd.rng.base, &cmd.riot, sessions_table, 2, NULL, 0,
		&cmd.keys_keystore.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cmd.session.base.add_session);
	CuAssertPtrNotNull (test, cmd.session.base.establish_session);
	CuAssertPtrNotNull (test, cmd.session.base.is_session_established);
	CuAssertPtrNotNull (test, cmd.session.base.get_pairing_state);
	CuAssertPtrNotNull (test, cmd.session.base.decrypt_message);
	CuAssertPtrNotNull (test, cmd.session.base.encrypt_message);
	CuAssertPtrNotNull (test, cmd.session.base.reset_session);
	CuAssertPtrNotNull (test, cmd.session.base.setup_paired_session);
	CuAssertPtrNotNull (test, cmd.session.base.session_sync);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_init_invalid_arg (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	int status;

	TEST_START;

	status = aes_mock_init (&cmd.aes);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&cmd.ecc);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&cmd.hash);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&cmd.rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&cmd.keys_keystore);
	CuAssertIntEquals (test, 0, status);

	status = session_manager_ecc_init (NULL, &cmd.aes.base, &cmd.ecc.base, &cmd.hash.base,
		&cmd.rng.base, &cmd.riot, NULL, 1, NULL, 0, &cmd.keys_keystore.base);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = session_manager_ecc_init (&cmd.session, NULL, &cmd.ecc.base, &cmd.hash.base,
		&cmd.rng.base, &cmd.riot, NULL, 1, NULL, 0,&cmd.keys_keystore.base);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = session_manager_ecc_init (&cmd.session, &cmd.aes.base, NULL, &cmd.hash.base,
		&cmd.rng.base, &cmd.riot, NULL, 1, NULL, 0,&cmd.keys_keystore.base);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = session_manager_ecc_init (&cmd.session, &cmd.aes.base, &cmd.ecc.base, NULL,
		&cmd.rng.base, &cmd.riot, NULL, 1, NULL, 0,&cmd.keys_keystore.base);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = session_manager_ecc_init (&cmd.session, &cmd.aes.base, &cmd.ecc.base, &cmd.hash.base,
		NULL, &cmd.riot, NULL, 1, NULL, 0,&cmd.keys_keystore.base);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = session_manager_ecc_init (&cmd.session, &cmd.aes.base, &cmd.ecc.base, &cmd.hash.base,
		&cmd.rng.base, NULL, NULL, 1, NULL, 0,&cmd.keys_keystore.base);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = aes_mock_validate_and_release (&cmd.aes);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&cmd.ecc);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&cmd.hash);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&cmd.rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&cmd.keys_keystore);
	CuAssertIntEquals (test, 0, status);
}

static void session_manager_ecc_test_release_null (CuTest *test)
{
	TEST_START;

	session_manager_ecc_release (NULL);
}

static void session_manager_ecc_test_add_session (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t nonce1[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_add_session_restart (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t nonce1[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_add_session_full (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t nonce1[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x20, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x30, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x40, nonce1, nonce2);
	CuAssertIntEquals (test, SESSION_MANAGER_FULL, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_add_session_invalid_arg (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t nonce1[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (NULL, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, NULL, nonce2);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, NULL);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	struct cerberus_protocol_key_exchange_type_0 *rq_ptr =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	struct cerberus_protocol_key_exchange_response_type_0 *rsp_ptr =
		(struct cerberus_protocol_key_exchange_response_type_0*) data;
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t session_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t hmac_key[] = {
		0xf1,0x3b,0x43,0x16,0xd5,0xc5,0xc6,0x10,0xad,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x37,
		0x0e,0x9a,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t digest[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0x0e,0x9a,0x37,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,
		0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0xd5,0xc5,0xc6
	};
	uint8_t hmac[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0xad,0xd5,0xc5,0xc6,0x9a,0x37,0xff,0x3e,0x75,
		0x0e,0x73,0xc5,0x54,0x10,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t *ecc_cerberus_key;
	uint32_t i_1 = platform_htonl (1);
	uint8_t separator = 0;
	uint32_t L = platform_htonl (256);
	int status;

	TEST_START;

	rq.data = data;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	rq.source_eid = 0x10;
	rq.length = cerberus_protocol_key_exchange_type_0_length (ECC_PUBKEY_DER_LEN);

	rq_ptr->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;
	rq_ptr->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (((uint8_t*) rq_ptr) + sizeof (struct cerberus_protocol_key_exchange_type_0),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);

	ecc_cerberus_key = platform_malloc (ECC_PUBKEY2_DER_LEN);
	CuAssertPtrNotNull (test, ecc_cerberus_key);

	memcpy (ecc_cerberus_key, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN);

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.generate_key_pair, &cmd.ecc, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 1, 1);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_public_key_der, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.ecc.mock, 1, &ecc_cerberus_key, sizeof (ecc_cerberus_key),
		-1);
	status |= mock_expect_output (&cmd.ecc.mock, 2, &ECC_PUBKEY2_DER_LEN,
		sizeof (ECC_PUBKEY2_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash, 0);
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN),
		MOCK_ARG (ECC_PUBKEY2_DER_LEN));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.finish, &cmd.hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&cmd.hash.mock, 0, digest, sizeof (digest), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 3);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_signature_max_length, &cmd.ecc, 91,
		MOCK_ARG_SAVED_ARG (3));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.sign, &cmd.ecc, ECC_SIG_TEST_LEN,
		MOCK_ARG_SAVED_ARG (3), MOCK_ARG_PTR_CONTAINS (digest, sizeof (digest)),
		MOCK_ARG (sizeof (digest)), MOCK_ARG_NOT_NULL, MOCK_ARG (rq.max_response -
		sizeof (struct cerberus_protocol_key_exchange_response_type_0) - ECC_PUBKEY2_DER_LEN -
		sizeof (uint16_t)));
	status |= mock_expect_output (&cmd.ecc.mock, 3, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.compute_shared_secret, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&cmd.ecc.mock, 2, SHARED_SECRET, sizeof (SHARED_SECRET), 3);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&i_1, sizeof (i_1)), MOCK_ARG (sizeof (i_1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce1, sizeof (nonce1)), MOCK_ARG (sizeof (nonce1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce2, sizeof (nonce2)), MOCK_ARG (sizeof (nonce2)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&L, sizeof (L)), MOCK_ARG (sizeof (L)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET),
		NULL, SHA256_HASH_LENGTH, session_key, sizeof (session_key));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&i_1, sizeof (i_1)), MOCK_ARG (sizeof (i_1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce2, sizeof (nonce2)), MOCK_ARG (sizeof (nonce2)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce1, sizeof (nonce1)), MOCK_ARG (sizeof (nonce1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&L, sizeof (L)), MOCK_ARG (sizeof (L)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET),
		NULL, SHA256_HASH_LENGTH, hmac_key, sizeof (hmac_key));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, hmac_key, sizeof (hmac_key));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, hmac_key, sizeof (hmac_key), NULL,
		rq.max_response - sizeof (struct cerberus_protocol_key_exchange_response_type_0) -
		ECC_PUBKEY2_DER_LEN - sizeof (uint16_t) * 2 - ECC_SIG_TEST_LEN, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (3), MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG (NULL), MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, &rq);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, cerberus_protocol_key_exchange_type_0_response_length (
		ECC_PUBKEY2_DER_LEN, ECC_SIG_TEST_LEN, SHA256_HASH_LENGTH), rq.length);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_SESSION_KEY, rsp_ptr->common.key_type);
	CuAssertIntEquals (test, 0, rsp_ptr->reserved);
	CuAssertIntEquals (test, ECC_PUBKEY2_DER_LEN, rsp_ptr->key_len);
	CuAssertIntEquals (test, ECC_SIG_TEST_LEN,
		cerberus_protocol_key_exchange_type_0_response_sig_len (rsp_ptr));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH,
		cerberus_protocol_key_exchange_type_0_response_hmac_len (rsp_ptr));

	status = testing_validate_array (ECC_PUBKEY2_DER,
		cerberus_protocol_key_exchange_type_0_response_key_data (rsp_ptr), ECC_PUBKEY2_DER_LEN);
	status |= testing_validate_array (ECC_SIGNATURE_TEST,
		cerberus_protocol_key_exchange_type_0_response_sig_data (rsp_ptr), ECC_SIG_TEST_LEN);
	status |= testing_validate_array (hmac,
		cerberus_protocol_key_exchange_type_0_response_hmac_data (rsp_ptr), sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_invalid_request (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	struct cerberus_protocol_key_exchange_type_0 *rq_ptr =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;

	TEST_START;

	rq.data = data;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	rq.source_eid = 0x10;
	rq.length = cerberus_protocol_key_exchange_type_0_length (0);

	rq_ptr->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;
	rq_ptr->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (((uint8_t*) rq_ptr) + sizeof (struct cerberus_protocol_key_exchange_type_0),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, &rq);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_REQUEST, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_buf_smaller_than_response (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	struct cerberus_protocol_key_exchange_type_0 *rq_ptr =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;

	TEST_START;

	rq.data = data;
	rq.max_response = sizeof (struct cerberus_protocol_key_exchange_response);
	rq.source_eid = 0x10;
	rq.length = cerberus_protocol_key_exchange_type_0_length (ECC_PUBKEY_DER_LEN);

	rq_ptr->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;
	rq_ptr->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (((uint8_t*) rq_ptr) + sizeof (struct cerberus_protocol_key_exchange_type_0),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, &rq);
	CuAssertIntEquals (test, SESSION_MANAGER_BUF_TOO_SMALL, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_invalid_order (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	struct cerberus_protocol_key_exchange_type_0 *rq_ptr =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	int status;

	TEST_START;

	rq.data = data;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	rq.source_eid = 0x10;
	rq.length = cerberus_protocol_key_exchange_type_0_length (ECC_PUBKEY2_DER_LEN);

	rq_ptr->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;
	rq_ptr->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (((uint8_t*) rq_ptr) + sizeof (struct cerberus_protocol_key_exchange_type_0),
		ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN);

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = cmd.session.base.establish_session (&cmd.session.base, &rq);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ORDER, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_unexpected_eid (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	struct cerberus_protocol_key_exchange_type_0 *rq_ptr =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;

	TEST_START;

	rq.data = data;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	rq.source_eid = 0x11;
	rq.length = cerberus_protocol_key_exchange_type_0_length (ECC_PUBKEY_DER_LEN);

	rq_ptr->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;
	rq_ptr->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (((uint8_t*) rq_ptr) + sizeof (struct cerberus_protocol_key_exchange_type_0),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, &rq);
	CuAssertIntEquals (test, SESSION_MANAGER_UNEXPECTED_EID, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_unsupported_hash_type (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	struct cerberus_protocol_key_exchange_type_0 *rq_ptr =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;

	TEST_START;

	rq.data = data;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	rq.source_eid = 0x10;
	rq.length = cerberus_protocol_key_exchange_type_0_length (ECC_PUBKEY_DER_LEN);

	rq_ptr->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;
	rq_ptr->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA384;

	memcpy (((uint8_t*) rq_ptr) + sizeof (struct cerberus_protocol_key_exchange_type_0),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, &rq);
	CuAssertIntEquals (test, SESSION_MANAGER_OPERATION_UNSUPPORTED, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_init_device_pub_key_fail (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	struct cerberus_protocol_key_exchange_type_0 *rq_ptr =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;

	TEST_START;

	rq.data = data;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	rq.source_eid = 0x10;
	rq.length = cerberus_protocol_key_exchange_type_0_length (ECC_PUBKEY_DER_LEN);

	rq_ptr->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;
	rq_ptr->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (((uint8_t*) rq_ptr) + sizeof (struct cerberus_protocol_key_exchange_type_0),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc,
		ECC_ENGINE_NO_MEMORY, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, &rq);
	CuAssertIntEquals (test, ECC_ENGINE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_generate_response_key_fail (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	struct cerberus_protocol_key_exchange_type_0 *rq_ptr =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;

	TEST_START;

	rq.data = data;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	rq.source_eid = 0x10;
	rq.length = cerberus_protocol_key_exchange_type_0_length (ECC_PUBKEY_DER_LEN);

	rq_ptr->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;
	rq_ptr->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (((uint8_t*) rq_ptr) + sizeof (struct cerberus_protocol_key_exchange_type_0),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.generate_key_pair, &cmd.ecc,
		ECC_ENGINE_NO_MEMORY, MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG (NULL), MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, &rq);
	CuAssertIntEquals (test, ECC_ENGINE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_get_session_key_der_fail (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	struct cerberus_protocol_key_exchange_type_0 *rq_ptr =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;

	TEST_START;

	rq.data = data;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	rq.source_eid = 0x10;
	rq.length = cerberus_protocol_key_exchange_type_0_length (ECC_PUBKEY_DER_LEN);

	rq_ptr->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;
	rq_ptr->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (((uint8_t*) rq_ptr) + sizeof (struct cerberus_protocol_key_exchange_type_0),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.generate_key_pair, &cmd.ecc, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 1, 1);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_public_key_der, &cmd.ecc,
		ECC_ENGINE_NO_MEMORY, MOCK_ARG_SAVED_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		 MOCK_ARG (NULL), MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, &rq);
	CuAssertIntEquals (test, ECC_ENGINE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_start_keys_digest_fail (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	struct cerberus_protocol_key_exchange_type_0 *rq_ptr =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t *ecc_cerberus_key;
	int status;

	TEST_START;

	rq.data = data;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	rq.source_eid = 0x10;
	rq.length = cerberus_protocol_key_exchange_type_0_length (ECC_PUBKEY_DER_LEN);

	rq_ptr->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;
	rq_ptr->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (((uint8_t*) rq_ptr) + sizeof (struct cerberus_protocol_key_exchange_type_0),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);

	ecc_cerberus_key = platform_malloc (ECC_PUBKEY2_DER_LEN);
	CuAssertPtrNotNull (test, ecc_cerberus_key);

	memcpy (ecc_cerberus_key, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN);

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.generate_key_pair, &cmd.ecc, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 1, 1);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_public_key_der, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.ecc.mock, 1, &ecc_cerberus_key, sizeof (ecc_cerberus_key),
		-1);
	status |= mock_expect_output (&cmd.ecc.mock, 2, &ECC_PUBKEY2_DER_LEN,
		sizeof (ECC_PUBKEY2_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash,
		HASH_ENGINE_NO_MEMORY);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		 MOCK_ARG (NULL), MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, &rq);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_update_keys_digest_device_key_fail (
	CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	struct cerberus_protocol_key_exchange_type_0 *rq_ptr =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t *ecc_cerberus_key;
	int status;

	TEST_START;

	rq.data = data;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	rq.source_eid = 0x10;
	rq.length = cerberus_protocol_key_exchange_type_0_length (ECC_PUBKEY_DER_LEN);

	rq_ptr->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;
	rq_ptr->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (((uint8_t*) rq_ptr) + sizeof (struct cerberus_protocol_key_exchange_type_0),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);

	ecc_cerberus_key = platform_malloc (ECC_PUBKEY2_DER_LEN);
	CuAssertPtrNotNull (test, ecc_cerberus_key);

	memcpy (ecc_cerberus_key, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN);

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.generate_key_pair, &cmd.ecc, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 1, 1);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_public_key_der, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.ecc.mock, 1, &ecc_cerberus_key, sizeof (ecc_cerberus_key),
		-1);
	status |= mock_expect_output (&cmd.ecc.mock, 2, &ECC_PUBKEY2_DER_LEN,
		sizeof (ECC_PUBKEY2_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash, 0);
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, HASH_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.cancel, &cmd.hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		 MOCK_ARG (NULL), MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, &rq);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_update_keys_digest_session_key_fail (
	CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	struct cerberus_protocol_key_exchange_type_0 *rq_ptr =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t *ecc_cerberus_key;
	int status;

	TEST_START;

	rq.data = data;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	rq.source_eid = 0x10;
	rq.length = cerberus_protocol_key_exchange_type_0_length (ECC_PUBKEY_DER_LEN);

	rq_ptr->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;
	rq_ptr->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (((uint8_t*) rq_ptr) + sizeof (struct cerberus_protocol_key_exchange_type_0),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);

	ecc_cerberus_key = platform_malloc (ECC_PUBKEY2_DER_LEN);
	CuAssertPtrNotNull (test, ecc_cerberus_key);

	memcpy (ecc_cerberus_key, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN);

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.generate_key_pair, &cmd.ecc, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 1, 1);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_public_key_der, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.ecc.mock, 1, &ecc_cerberus_key, sizeof (ecc_cerberus_key),
		-1);
	status |= mock_expect_output (&cmd.ecc.mock, 2, &ECC_PUBKEY2_DER_LEN,
		sizeof (ECC_PUBKEY2_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash, 0);
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, HASH_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN),
		MOCK_ARG (ECC_PUBKEY2_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.cancel, &cmd.hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		 MOCK_ARG (NULL), MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, &rq);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_finish_keys_digest_fail (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	struct cerberus_protocol_key_exchange_type_0 *rq_ptr =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t *ecc_cerberus_key;
	int status;

	TEST_START;

	rq.data = data;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	rq.source_eid = 0x10;
	rq.length = cerberus_protocol_key_exchange_type_0_length (ECC_PUBKEY_DER_LEN);

	rq_ptr->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;
	rq_ptr->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (((uint8_t*) rq_ptr) + sizeof (struct cerberus_protocol_key_exchange_type_0),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);

	ecc_cerberus_key = platform_malloc (ECC_PUBKEY2_DER_LEN);
	CuAssertPtrNotNull (test, ecc_cerberus_key);

	memcpy (ecc_cerberus_key, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN);

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.generate_key_pair, &cmd.ecc, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 1, 1);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_public_key_der, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.ecc.mock, 1, &ecc_cerberus_key, sizeof (ecc_cerberus_key),
		-1);
	status |= mock_expect_output (&cmd.ecc.mock, 2, &ECC_PUBKEY2_DER_LEN,
		sizeof (ECC_PUBKEY2_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash, 0);
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN),
		MOCK_ARG (ECC_PUBKEY2_DER_LEN));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.finish, &cmd.hash, HASH_ENGINE_NO_MEMORY,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.cancel, &cmd.hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		 MOCK_ARG (NULL), MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, &rq);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_buf_smaller_than_session_key (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	struct cerberus_protocol_key_exchange_type_0 *rq_ptr =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t digest[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0x0e,0x9a,0x37,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,
		0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0xd5,0xc5,0xc6
	};
	uint8_t *ecc_cerberus_key;
	int status;

	TEST_START;

	rq.data = data;
	rq.max_response = sizeof (struct cerberus_protocol_key_exchange_response_type_0) +
		ECC_PUBKEY2_DER_LEN;
	rq.source_eid = 0x10;
	rq.length = cerberus_protocol_key_exchange_type_0_length (ECC_PUBKEY_DER_LEN);

	rq_ptr->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;
	rq_ptr->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (((uint8_t*) rq_ptr) + sizeof (struct cerberus_protocol_key_exchange_type_0),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);

	ecc_cerberus_key = platform_malloc (ECC_PUBKEY2_DER_LEN);
	CuAssertPtrNotNull (test, ecc_cerberus_key);

	memcpy (ecc_cerberus_key, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN);

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.generate_key_pair, &cmd.ecc, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 1, 1);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_public_key_der, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.ecc.mock, 1, &ecc_cerberus_key, sizeof (ecc_cerberus_key),
		-1);
	status |= mock_expect_output (&cmd.ecc.mock, 2, &ECC_PUBKEY2_DER_LEN,
		sizeof (ECC_PUBKEY2_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash, 0);
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN),
		MOCK_ARG (ECC_PUBKEY2_DER_LEN));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.finish, &cmd.hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&cmd.hash.mock, 0, digest, sizeof (digest), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		 MOCK_ARG (NULL), MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, &rq);
	CuAssertIntEquals (test, SESSION_MANAGER_BUF_TOO_SMALL, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_init_alias_priv_key_fail (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	struct cerberus_protocol_key_exchange_type_0 *rq_ptr =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t digest[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0x0e,0x9a,0x37,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,
		0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0xd5,0xc5,0xc6
	};
	uint8_t *ecc_cerberus_key;
	int status;

	TEST_START;

	rq.data = data;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	rq.source_eid = 0x10;
	rq.length = cerberus_protocol_key_exchange_type_0_length (ECC_PUBKEY_DER_LEN);

	rq_ptr->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;
	rq_ptr->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (((uint8_t*) rq_ptr) + sizeof (struct cerberus_protocol_key_exchange_type_0),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);

	ecc_cerberus_key = platform_malloc (ECC_PUBKEY2_DER_LEN);
	CuAssertPtrNotNull (test, ecc_cerberus_key);

	memcpy (ecc_cerberus_key, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN);

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.generate_key_pair, &cmd.ecc, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 1, 1);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_public_key_der, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.ecc.mock, 1, &ecc_cerberus_key, sizeof (ecc_cerberus_key),
		-1);
	status |= mock_expect_output (&cmd.ecc.mock, 2, &ECC_PUBKEY2_DER_LEN,
		sizeof (ECC_PUBKEY2_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash, 0);
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN),
		MOCK_ARG (ECC_PUBKEY2_DER_LEN));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.finish, &cmd.hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&cmd.hash.mock, 0, digest, sizeof (digest), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, ECC_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		 MOCK_ARG (NULL), MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, &rq);
	CuAssertIntEquals (test, ECC_ENGINE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_get_max_sig_len_fail (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	struct cerberus_protocol_key_exchange_type_0 *rq_ptr =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t digest[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0x0e,0x9a,0x37,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,
		0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0xd5,0xc5,0xc6
	};
	uint8_t *ecc_cerberus_key;
	int status;

	TEST_START;

	rq.data = data;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	rq.source_eid = 0x10;
	rq.length = cerberus_protocol_key_exchange_type_0_length (ECC_PUBKEY_DER_LEN);

	rq_ptr->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;
	rq_ptr->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (((uint8_t*) rq_ptr) + sizeof (struct cerberus_protocol_key_exchange_type_0),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);

	ecc_cerberus_key = platform_malloc (ECC_PUBKEY2_DER_LEN);
	CuAssertPtrNotNull (test, ecc_cerberus_key);

	memcpy (ecc_cerberus_key, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN);

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.generate_key_pair, &cmd.ecc, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 1, 1);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_public_key_der, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.ecc.mock, 1, &ecc_cerberus_key, sizeof (ecc_cerberus_key),
		-1);
	status |= mock_expect_output (&cmd.ecc.mock, 2, &ECC_PUBKEY2_DER_LEN,
		sizeof (ECC_PUBKEY2_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash, 0);
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN),
		MOCK_ARG (ECC_PUBKEY2_DER_LEN));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.finish, &cmd.hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&cmd.hash.mock, 0, digest, sizeof (digest), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 3);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_signature_max_length, &cmd.ecc,
		ECC_ENGINE_NO_MEMORY, MOCK_ARG_SAVED_ARG (3));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (3), MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		 MOCK_ARG (NULL), MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, &rq);
	CuAssertIntEquals (test, ECC_ENGINE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_sign_fail (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	struct cerberus_protocol_key_exchange_type_0 *rq_ptr =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t digest[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0x0e,0x9a,0x37,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,
		0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0xd5,0xc5,0xc6
	};
	uint8_t *ecc_cerberus_key;
	int status;

	TEST_START;

	rq.data = data;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	rq.source_eid = 0x10;
	rq.length = cerberus_protocol_key_exchange_type_0_length (ECC_PUBKEY_DER_LEN);

	rq_ptr->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;
	rq_ptr->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (((uint8_t*) rq_ptr) + sizeof (struct cerberus_protocol_key_exchange_type_0),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);

	ecc_cerberus_key = platform_malloc (ECC_PUBKEY2_DER_LEN);
	CuAssertPtrNotNull (test, ecc_cerberus_key);

	memcpy (ecc_cerberus_key, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN);

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.generate_key_pair, &cmd.ecc, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 1, 1);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_public_key_der, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.ecc.mock, 1, &ecc_cerberus_key, sizeof (ecc_cerberus_key),
		-1);
	status |= mock_expect_output (&cmd.ecc.mock, 2, &ECC_PUBKEY2_DER_LEN,
		sizeof (ECC_PUBKEY2_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash, 0);
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN),
		MOCK_ARG (ECC_PUBKEY2_DER_LEN));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.finish, &cmd.hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&cmd.hash.mock, 0, digest, sizeof (digest), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 3);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_signature_max_length, &cmd.ecc, 91,
		MOCK_ARG_SAVED_ARG (3));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.sign, &cmd.ecc, ECC_ENGINE_NO_MEMORY,
		MOCK_ARG_SAVED_ARG (3), MOCK_ARG_PTR_CONTAINS (digest, sizeof (digest)),
		MOCK_ARG (sizeof (digest)), MOCK_ARG_NOT_NULL, MOCK_ARG (rq.max_response -
		sizeof (struct cerberus_protocol_key_exchange_response_type_0) - ECC_PUBKEY2_DER_LEN -
		sizeof (uint16_t)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (3), MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		 MOCK_ARG (NULL), MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, &rq);
	CuAssertIntEquals (test, ECC_ENGINE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_size_shared_secret_fail (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	struct cerberus_protocol_key_exchange_type_0 *rq_ptr =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t digest[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0x0e,0x9a,0x37,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,
		0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0xd5,0xc5,0xc6
	};
	uint8_t *ecc_cerberus_key;
	int status;

	TEST_START;

	rq.data = data;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	rq.source_eid = 0x10;
	rq.length = cerberus_protocol_key_exchange_type_0_length (ECC_PUBKEY_DER_LEN);

	rq_ptr->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;
	rq_ptr->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (((uint8_t*) rq_ptr) + sizeof (struct cerberus_protocol_key_exchange_type_0),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);

	ecc_cerberus_key = platform_malloc (ECC_PUBKEY2_DER_LEN);
	CuAssertPtrNotNull (test, ecc_cerberus_key);

	memcpy (ecc_cerberus_key, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN);

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.generate_key_pair, &cmd.ecc, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 1, 1);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_public_key_der, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.ecc.mock, 1, &ecc_cerberus_key, sizeof (ecc_cerberus_key),
		-1);
	status |= mock_expect_output (&cmd.ecc.mock, 2, &ECC_PUBKEY2_DER_LEN,
		sizeof (ECC_PUBKEY2_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash, 0);
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN),
		MOCK_ARG (ECC_PUBKEY2_DER_LEN));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.finish, &cmd.hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&cmd.hash.mock, 0, digest, sizeof (digest), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 3);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_signature_max_length, &cmd.ecc, 91,
		MOCK_ARG_SAVED_ARG (3));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.sign, &cmd.ecc, ECC_SIG_TEST_LEN,
		MOCK_ARG_SAVED_ARG (3), MOCK_ARG_PTR_CONTAINS (digest, sizeof (digest)),
		MOCK_ARG (sizeof (digest)), MOCK_ARG_NOT_NULL, MOCK_ARG (rq.max_response -
		sizeof (struct cerberus_protocol_key_exchange_response_type_0) - ECC_PUBKEY2_DER_LEN -
		sizeof (uint16_t)));
	status |= mock_expect_output (&cmd.ecc.mock, 3, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc,
		ECC_ENGINE_NO_MEMORY, MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (3), MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		 MOCK_ARG (NULL), MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, &rq);
	CuAssertIntEquals (test, ECC_ENGINE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_compute_shared_secret_fail (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	struct cerberus_protocol_key_exchange_type_0 *rq_ptr =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t digest[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0x0e,0x9a,0x37,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,
		0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0xd5,0xc5,0xc6
	};
	uint8_t *ecc_cerberus_key;
	int status;

	TEST_START;

	rq.data = data;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	rq.source_eid = 0x10;
	rq.length = cerberus_protocol_key_exchange_type_0_length (ECC_PUBKEY_DER_LEN);

	rq_ptr->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;
	rq_ptr->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (((uint8_t*) rq_ptr) + sizeof (struct cerberus_protocol_key_exchange_type_0),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);

	ecc_cerberus_key = platform_malloc (ECC_PUBKEY2_DER_LEN);
	CuAssertPtrNotNull (test, ecc_cerberus_key);

	memcpy (ecc_cerberus_key, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN);

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.generate_key_pair, &cmd.ecc, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 1, 1);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_public_key_der, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.ecc.mock, 1, &ecc_cerberus_key, sizeof (ecc_cerberus_key),
		-1);
	status |= mock_expect_output (&cmd.ecc.mock, 2, &ECC_PUBKEY2_DER_LEN,
		sizeof (ECC_PUBKEY2_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash, 0);
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN),
		MOCK_ARG (ECC_PUBKEY2_DER_LEN));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.finish, &cmd.hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&cmd.hash.mock, 0, digest, sizeof (digest), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 3);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_signature_max_length, &cmd.ecc, 91,
		MOCK_ARG_SAVED_ARG (3));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.sign, &cmd.ecc, ECC_SIG_TEST_LEN,
		MOCK_ARG_SAVED_ARG (3), MOCK_ARG_PTR_CONTAINS (digest, sizeof (digest)),
		MOCK_ARG (sizeof (digest)), MOCK_ARG_NOT_NULL, MOCK_ARG (rq.max_response -
		sizeof (struct cerberus_protocol_key_exchange_response_type_0) - ECC_PUBKEY2_DER_LEN -
		sizeof (uint16_t)));
	status |= mock_expect_output (&cmd.ecc.mock, 3, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.compute_shared_secret, &cmd.ecc,
		ECC_ENGINE_NO_MEMORY, MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL,
		MOCK_ARG (64));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (3), MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		 MOCK_ARG (NULL), MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, &rq);
	CuAssertIntEquals (test, ECC_ENGINE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_generate_session_key_fail (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	struct cerberus_protocol_key_exchange_type_0 *rq_ptr =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t digest[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0x0e,0x9a,0x37,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,
		0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0xd5,0xc5,0xc6
	};
	uint8_t *ecc_cerberus_key;
	int status;

	TEST_START;

	rq.data = data;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	rq.source_eid = 0x10;
	rq.length = cerberus_protocol_key_exchange_type_0_length (ECC_PUBKEY_DER_LEN);

	rq_ptr->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;
	rq_ptr->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (((uint8_t*) rq_ptr) + sizeof (struct cerberus_protocol_key_exchange_type_0),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);

	ecc_cerberus_key = platform_malloc (ECC_PUBKEY2_DER_LEN);
	CuAssertPtrNotNull (test, ecc_cerberus_key);

	memcpy (ecc_cerberus_key, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN);

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.generate_key_pair, &cmd.ecc, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 1, 1);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_public_key_der, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.ecc.mock, 1, &ecc_cerberus_key, sizeof (ecc_cerberus_key),
		-1);
	status |= mock_expect_output (&cmd.ecc.mock, 2, &ECC_PUBKEY2_DER_LEN,
		sizeof (ECC_PUBKEY2_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash, 0);
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN),
		MOCK_ARG (ECC_PUBKEY2_DER_LEN));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.finish, &cmd.hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&cmd.hash.mock, 0, digest, sizeof (digest), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 3);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_signature_max_length, &cmd.ecc, 91,
		MOCK_ARG_SAVED_ARG (3));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.sign, &cmd.ecc, ECC_SIG_TEST_LEN,
		MOCK_ARG_SAVED_ARG (3), MOCK_ARG_PTR_CONTAINS (digest, sizeof (digest)),
		MOCK_ARG (sizeof (digest)), MOCK_ARG_NOT_NULL, MOCK_ARG (rq.max_response -
		sizeof (struct cerberus_protocol_key_exchange_response_type_0) - ECC_PUBKEY2_DER_LEN -
		sizeof (uint16_t)));
	status |= mock_expect_output (&cmd.ecc.mock, 3, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.compute_shared_secret, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&cmd.ecc.mock, 2, SHARED_SECRET, sizeof (SHARED_SECRET), 3);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash,
		HASH_ENGINE_NO_MEMORY);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (3), MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		 MOCK_ARG (NULL), MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, &rq);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_generate_hmac_key_fail (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	struct cerberus_protocol_key_exchange_type_0 *rq_ptr =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t session_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t digest[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0x0e,0x9a,0x37,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,
		0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0xd5,0xc5,0xc6
	};
	uint32_t i_1 = platform_htonl (1);
	uint8_t separator = 0;
	uint32_t L = platform_htonl (256);
	uint8_t *ecc_cerberus_key;
	int status;

	TEST_START;

	rq.data = data;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	rq.source_eid = 0x10;
	rq.length = cerberus_protocol_key_exchange_type_0_length (ECC_PUBKEY_DER_LEN);

	rq_ptr->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;
	rq_ptr->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (((uint8_t*) rq_ptr) + sizeof (struct cerberus_protocol_key_exchange_type_0),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);

	ecc_cerberus_key = platform_malloc (ECC_PUBKEY2_DER_LEN);
	CuAssertPtrNotNull (test, ecc_cerberus_key);

	memcpy (ecc_cerberus_key, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN);

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.generate_key_pair, &cmd.ecc, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 1, 1);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_public_key_der, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.ecc.mock, 1, &ecc_cerberus_key, sizeof (ecc_cerberus_key),
		-1);
	status |= mock_expect_output (&cmd.ecc.mock, 2, &ECC_PUBKEY2_DER_LEN,
		sizeof (ECC_PUBKEY2_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash, 0);
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN),
		MOCK_ARG (ECC_PUBKEY2_DER_LEN));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.finish, &cmd.hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&cmd.hash.mock, 0, digest, sizeof (digest), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 3);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_signature_max_length, &cmd.ecc, 91,
		MOCK_ARG_SAVED_ARG (3));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.sign, &cmd.ecc, ECC_SIG_TEST_LEN,
		MOCK_ARG_SAVED_ARG (3), MOCK_ARG_PTR_CONTAINS (digest, sizeof (digest)),
		MOCK_ARG (sizeof (digest)), MOCK_ARG_NOT_NULL, MOCK_ARG (rq.max_response -
		sizeof (struct cerberus_protocol_key_exchange_response_type_0) - ECC_PUBKEY2_DER_LEN -
		sizeof (uint16_t)));
	status |= mock_expect_output (&cmd.ecc.mock, 3, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.compute_shared_secret, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&cmd.ecc.mock, 2, SHARED_SECRET, sizeof (SHARED_SECRET), 3);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&i_1, sizeof (i_1)), MOCK_ARG (sizeof (i_1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce1, sizeof (nonce1)), MOCK_ARG (sizeof (nonce1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce2, sizeof (nonce2)), MOCK_ARG (sizeof (nonce2)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&L, sizeof (L)), MOCK_ARG (sizeof (L)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET),
		NULL, SHA256_HASH_LENGTH, session_key, sizeof (session_key));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash,
		HASH_ENGINE_NO_MEMORY);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (3), MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		 MOCK_ARG (NULL), MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, &rq);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_generate_hmac_fail (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	struct cerberus_protocol_key_exchange_type_0 *rq_ptr =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t session_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t hmac_key[] = {
		0xf1,0x3b,0x43,0x16,0xd5,0xc5,0xc6,0x10,0xad,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x37,
		0x0e,0x9a,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t digest[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0x0e,0x9a,0x37,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,
		0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0xd5,0xc5,0xc6
	};
	uint8_t *ecc_cerberus_key;
	uint32_t i_1 = platform_htonl (1);
	uint8_t separator = 0;
	uint32_t L = platform_htonl (256);
	int status;

	TEST_START;

	rq.data = data;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	rq.source_eid = 0x10;
	rq.length = cerberus_protocol_key_exchange_type_0_length (ECC_PUBKEY_DER_LEN);

	rq_ptr->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;
	rq_ptr->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (((uint8_t*) rq_ptr) + sizeof (struct cerberus_protocol_key_exchange_type_0),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);

	ecc_cerberus_key = platform_malloc (ECC_PUBKEY2_DER_LEN);
	CuAssertPtrNotNull (test, ecc_cerberus_key);

	memcpy (ecc_cerberus_key, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN);

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.generate_key_pair, &cmd.ecc, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 1, 1);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_public_key_der, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.ecc.mock, 1, &ecc_cerberus_key, sizeof (ecc_cerberus_key),
		-1);
	status |= mock_expect_output (&cmd.ecc.mock, 2, &ECC_PUBKEY2_DER_LEN,
		sizeof (ECC_PUBKEY2_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash, 0);
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN),
		MOCK_ARG (ECC_PUBKEY2_DER_LEN));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.finish, &cmd.hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&cmd.hash.mock, 0, digest, sizeof (digest), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 3);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_signature_max_length, &cmd.ecc, 91,
		MOCK_ARG_SAVED_ARG (3));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.sign, &cmd.ecc, ECC_SIG_TEST_LEN,
		MOCK_ARG_SAVED_ARG (3), MOCK_ARG_PTR_CONTAINS (digest, sizeof (digest)),
		MOCK_ARG (sizeof (digest)), MOCK_ARG_NOT_NULL, MOCK_ARG (rq.max_response -
		sizeof (struct cerberus_protocol_key_exchange_response_type_0) - ECC_PUBKEY2_DER_LEN -
		sizeof (uint16_t)));
	status |= mock_expect_output (&cmd.ecc.mock, 3, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.compute_shared_secret, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&cmd.ecc.mock, 2, SHARED_SECRET, sizeof (SHARED_SECRET), 3);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&i_1, sizeof (i_1)), MOCK_ARG (sizeof (i_1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce1, sizeof (nonce1)), MOCK_ARG (sizeof (nonce1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce2, sizeof (nonce2)), MOCK_ARG (sizeof (nonce2)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&L, sizeof (L)), MOCK_ARG (sizeof (L)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET),
		NULL, SHA256_HASH_LENGTH, session_key, sizeof (session_key));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&i_1, sizeof (i_1)), MOCK_ARG (sizeof (i_1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce2, sizeof (nonce2)), MOCK_ARG (sizeof (nonce2)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce1, sizeof (nonce1)), MOCK_ARG (sizeof (nonce1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&L, sizeof (L)), MOCK_ARG (sizeof (L)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET),
		NULL, SHA256_HASH_LENGTH, hmac_key, sizeof (hmac_key));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash,
		HASH_ENGINE_NO_MEMORY);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (3), MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		 MOCK_ARG (NULL), MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, &rq);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_invalid_arg (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	struct cmd_interface_msg rq;
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.establish_session (NULL, &rq);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = cmd.session.base.establish_session (&cmd.session.base, NULL);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_decrypt_message (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t rq_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	uint8_t data[] = {
		0xA,0xB,0xC,0xD,0xE,0xF,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
	};
	uint8_t decrypted[] = {
		0x6,0x7,0x8,0x9,0xA,0xB,0xC
	};
	uint8_t aes_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;

	TEST_START;

	rq.data = rq_data;
	memcpy (rq.data, data, sizeof (data));
	memcpy (rq.data + sizeof (data), SESSION_AES_GCM_TAG, sizeof (SESSION_AES_GCM_TAG));
	memcpy (rq.data + sizeof (data) + sizeof (SESSION_AES_GCM_TAG), SESSION_AES_IV,
		sizeof (SESSION_AES_IV));

	rq.length = 40;
	rq.source_eid = 0x10;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = mock_expect (&cmd.aes.mock, cmd.aes.base.set_key, &cmd.aes, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (aes_key, sizeof (aes_key)), MOCK_ARG (sizeof (aes_key)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.aes.mock, cmd.aes.base.decrypt_data, &cmd.aes, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (rq.data + sizeof (struct cerberus_protocol_header),
			sizeof (data) - sizeof (struct cerberus_protocol_header)),
		MOCK_ARG (sizeof (data) - sizeof (struct cerberus_protocol_header)),
		MOCK_ARG_PTR_CONTAINS (SESSION_AES_GCM_TAG, sizeof (SESSION_AES_GCM_TAG)),
		MOCK_ARG_PTR_CONTAINS (SESSION_AES_IV, sizeof (SESSION_AES_IV)),
		MOCK_ARG (sizeof (SESSION_AES_IV)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - sizeof (struct cerberus_protocol_header)));
	status |= mock_expect_output (&cmd.aes.mock, 5, decrypted, sizeof (decrypted), 6);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.decrypt_message (&cmd.session.base, &rq);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (data), rq.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY, rq.max_response);

	status = testing_validate_array (data, rq.data, sizeof (struct cerberus_protocol_header));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (decrypted, rq.data + sizeof (struct cerberus_protocol_header),
		sizeof (decrypted));
	CuAssertIntEquals (test, 0, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_decrypt_message_unexpected_eid (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	rq.data = data;
	rq.length = 40;
	rq.source_eid = 0x11;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	status = cmd.session.base.decrypt_message (&cmd.session.base, &rq);
	CuAssertIntEquals (test, SESSION_MANAGER_UNEXPECTED_EID, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_decrypt_message_session_not_established (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	rq.data = data;
	rq.length = 40;
	rq.source_eid = 0x10;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.decrypt_message (&cmd.session.base, &rq);
	CuAssertIntEquals (test, SESSION_MANAGER_SESSION_NOT_ESTABLISHED, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_decrypt_message_set_key_fail (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	uint8_t aes_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	rq.data = data;
	rq.length = 40;
	rq.source_eid = 0x10;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = mock_expect (&cmd.aes.mock, cmd.aes.base.set_key, &cmd.aes, AES_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS_TMP (aes_key, sizeof (aes_key)), MOCK_ARG (sizeof (aes_key)));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.decrypt_message (&cmd.session.base, &rq);
	CuAssertIntEquals (test, AES_ENGINE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_decrypt_message_fail (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t rq_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	uint8_t data[] = {
		0xA,0xB,0xC,0xD,0xE,0xF,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
	};
	uint8_t aes_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;

	TEST_START;

	rq.data = rq_data;
	memcpy (rq.data, data, sizeof (data));
	memcpy (rq.data + sizeof (data), SESSION_AES_GCM_TAG, sizeof (SESSION_AES_GCM_TAG));
	memcpy (rq.data + sizeof (data) + sizeof (SESSION_AES_GCM_TAG), SESSION_AES_IV,
		sizeof (SESSION_AES_IV));

	rq.length = 40;
	rq.source_eid = 0x10;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = mock_expect (&cmd.aes.mock, cmd.aes.base.set_key, &cmd.aes, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (aes_key, sizeof (aes_key)), MOCK_ARG (sizeof (aes_key)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.aes.mock, cmd.aes.base.decrypt_data, &cmd.aes,
		AES_ENGINE_NO_MEMORY, MOCK_ARG_PTR_CONTAINS (rq.data +
			sizeof (struct cerberus_protocol_header),
			sizeof (data) - sizeof (struct cerberus_protocol_header)),
		MOCK_ARG (sizeof (data) - sizeof (struct cerberus_protocol_header)),
		MOCK_ARG_PTR_CONTAINS (SESSION_AES_GCM_TAG, sizeof (SESSION_AES_GCM_TAG)),
		MOCK_ARG_PTR_CONTAINS (SESSION_AES_IV, sizeof (SESSION_AES_IV)),
		MOCK_ARG (sizeof (SESSION_AES_IV)), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.decrypt_message (&cmd.session.base, &rq);
	CuAssertIntEquals (test, AES_ENGINE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_decrypt_message_invalid_message (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	rq.data = data;
	rq.length = SESSION_MANAGER_TRAILER_LEN + sizeof (struct cerberus_protocol_header);
	rq.source_eid = 0x10;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	status = cmd.session.base.decrypt_message (&cmd.session.base, &rq);
	CuAssertIntEquals (test, SESSION_MANAGER_MALFORMED_MSG, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_decrypt_message_buf_too_small (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	rq.data = data;
	rq.length = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY + SESSION_MANAGER_TRAILER_LEN + 1;
	rq.source_eid = 0x10;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	status = cmd.session.base.decrypt_message (&cmd.session.base, &rq);
	CuAssertIntEquals (test, SESSION_MANAGER_BUF_TOO_SMALL, status);

	rq.length = SESSION_MANAGER_TRAILER_LEN + sizeof (struct cerberus_protocol_header) + 1;
	rq.source_eid = 0x10;
	rq.max_response = SESSION_MANAGER_TRAILER_LEN + sizeof (struct cerberus_protocol_header);

	status = cmd.session.base.decrypt_message (&cmd.session.base, &rq);
	CuAssertIntEquals (test, SESSION_MANAGER_BUF_TOO_SMALL, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_decrypt_message_invalid_arg (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	struct cmd_interface_msg rq;
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.decrypt_message (NULL, &rq);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = cmd.session.base.decrypt_message (&cmd.session.base, NULL);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_encrypt_message (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t rq_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	uint8_t data[] = {
		0xA,0xB,0xC,0xD,0xE,0xF,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
	};
	struct cerberus_protocol_header header;
	uint8_t encrypted[] = {
		0x1,0x2,0x3,0x4,0x5,0x6,0x7
	};
	uint8_t aes_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;

	TEST_START;

	rq.data = rq_data;
	memcpy (rq.data, data, sizeof (data));
	memcpy (&header, data, sizeof (struct cerberus_protocol_header));

	header.crypt = 1;

	rq.length = sizeof (data);
	rq.source_eid = 0x10;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = mock_expect (&cmd.aes.mock, cmd.aes.base.set_key, &cmd.aes, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (aes_key, sizeof (aes_key)), MOCK_ARG (sizeof (aes_key)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.rng.mock, cmd.rng.base.generate_random_buffer, &cmd.rng, 0,
		MOCK_ARG (sizeof (SESSION_AES_IV)), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.rng.mock, 1, SESSION_AES_IV, sizeof (SESSION_AES_IV), 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.aes.mock, cmd.aes.base.encrypt_data, &cmd.aes, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (data + sizeof (struct cerberus_protocol_header),
			sizeof (data) - sizeof (struct cerberus_protocol_header)),
		MOCK_ARG (sizeof (data) - sizeof (struct cerberus_protocol_header)),
		MOCK_ARG_PTR_CONTAINS (SESSION_AES_IV, sizeof (SESSION_AES_IV)),
		MOCK_ARG (sizeof (SESSION_AES_IV)), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY, MOCK_ARG_NOT_NULL,
		MOCK_ARG_ANY);
	status |= mock_expect_output (&cmd.aes.mock, 4, encrypted, sizeof (encrypted), 5);
	status |= mock_expect_output (&cmd.aes.mock, 6, SESSION_AES_GCM_TAG,
		sizeof (SESSION_AES_GCM_TAG), -1);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.encrypt_message (&cmd.session.base, &rq);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (data) + CERBERUS_PROTOCOL_AES_GCM_TAG_LEN +
		CERBERUS_PROTOCOL_AES_IV_LEN, rq.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY, rq.max_response);

	status = testing_validate_array ((uint8_t*) &header, rq.data,
		sizeof (struct cerberus_protocol_header));
	CuAssertIntEquals (test, 0, status);
	status = testing_validate_array (encrypted,
		rq.data + sizeof (struct cerberus_protocol_header), sizeof (encrypted));
	CuAssertIntEquals (test, 0, status);
	status = testing_validate_array (SESSION_AES_GCM_TAG,
		rq.data + sizeof (struct cerberus_protocol_header) + sizeof (encrypted),
		sizeof (SESSION_AES_GCM_TAG));
	CuAssertIntEquals (test, 0, status);
	status = testing_validate_array (SESSION_AES_IV, rq.data +
		sizeof (struct cerberus_protocol_header) + sizeof (encrypted) +
		sizeof (SESSION_AES_GCM_TAG), sizeof (SESSION_AES_IV));
	CuAssertIntEquals (test, 0, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_encrypt_message_unexpected_eid (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	struct cmd_interface_msg rq;
	uint8_t data[] = {
		0xA,0xB,0xC,0xD,0xE,0xF,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
	};
	int status;

	TEST_START;

	rq.data = data;
	rq.length = sizeof (data);
	rq.source_eid = 0x11;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.encrypt_message (&cmd.session.base, &rq);
	CuAssertIntEquals (test, SESSION_MANAGER_UNEXPECTED_EID, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_encrypt_message_session_not_established (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	struct cmd_interface_msg rq;
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t data[] = {
		0xA,0xB,0xC,0xD,0xE,0xF,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
	};
	int status;

	TEST_START;

	rq.data = data;
	rq.length = sizeof (data);
	rq.source_eid = 0x10;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.encrypt_message (&cmd.session.base, &rq);
	CuAssertIntEquals (test, SESSION_MANAGER_SESSION_NOT_ESTABLISHED, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_encrypt_message_set_key_fail (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	struct cmd_interface_msg rq;
	uint8_t data[] = {
		0xA,0xB,0xC,0xD,0xE,0xF,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
	};
	uint8_t aes_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;

	TEST_START;

	rq.data = data;
	rq.length = sizeof (data);
	rq.source_eid = 0x10;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = mock_expect (&cmd.aes.mock, cmd.aes.base.set_key, &cmd.aes, AES_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS_TMP (aes_key, sizeof (aes_key)), MOCK_ARG (sizeof (aes_key)));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.encrypt_message (&cmd.session.base, &rq);
	CuAssertIntEquals (test, AES_ENGINE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_encrypt_message_generate_iv_fail (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	struct cmd_interface_msg rq;
	uint8_t data[] = {
		0xA,0xB,0xC,0xD,0xE,0xF,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
	};
	uint8_t aes_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;

	TEST_START;

	rq.data = data;
	rq.length = sizeof (data);
	rq.source_eid = 0x10;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = mock_expect (&cmd.aes.mock, cmd.aes.base.set_key, &cmd.aes, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (aes_key, sizeof (aes_key)), MOCK_ARG (sizeof (aes_key)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.rng.mock, cmd.rng.base.generate_random_buffer, &cmd.rng,
		RNG_ENGINE_NO_MEMORY, MOCK_ARG (sizeof (SESSION_AES_IV)), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.rng.mock, 1, SESSION_AES_IV, sizeof (SESSION_AES_IV), 0);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.encrypt_message (&cmd.session.base, &rq);
	CuAssertIntEquals (test, RNG_ENGINE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_encrypt_message_fail (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	struct cmd_interface_msg rq;
	uint8_t data[] = {
		0xA,0xB,0xC,0xD,0xE,0xF,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
	};
	uint8_t aes_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;

	TEST_START;

	rq.data = data;
	rq.length = sizeof (data);
	rq.source_eid = 0x10;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = mock_expect (&cmd.aes.mock, cmd.aes.base.set_key, &cmd.aes, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (aes_key, sizeof (aes_key)), MOCK_ARG (sizeof (aes_key)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.rng.mock, cmd.rng.base.generate_random_buffer, &cmd.rng, 0,
		MOCK_ARG (sizeof (SESSION_AES_IV)), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.rng.mock, 1, SESSION_AES_IV, sizeof (SESSION_AES_IV), 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.aes.mock, cmd.aes.base.encrypt_data, &cmd.aes,
		AES_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS (data + sizeof (struct cerberus_protocol_header),
			sizeof (data) - sizeof (struct cerberus_protocol_header)),
		MOCK_ARG (sizeof (data) - sizeof (struct cerberus_protocol_header)),
		MOCK_ARG_PTR_CONTAINS (SESSION_AES_IV, sizeof (SESSION_AES_IV)),
		MOCK_ARG (sizeof (SESSION_AES_IV)), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY, MOCK_ARG_NOT_NULL,
		MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.encrypt_message (&cmd.session.base, &rq);
	CuAssertIntEquals (test, AES_ENGINE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_encrypt_message_no_payload (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	rq.data = data;
	rq.length = sizeof (struct cerberus_protocol_header);
	rq.source_eid = 0x10;
	rq.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	status = cmd.session.base.encrypt_message (&cmd.session.base, &rq);
	CuAssertIntEquals (test, 0, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_encrypt_message_buf_too_small (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg rq;
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	rq.data = data;
	rq.length = sizeof (struct cerberus_protocol_header) + 1;
	rq.max_response = rq.length + SESSION_MANAGER_TRAILER_LEN - 1;
	rq.source_eid = 0x10;

	status = cmd.session.base.encrypt_message (&cmd.session.base, &rq);
	CuAssertIntEquals (test, SESSION_MANAGER_BUF_TOO_SMALL, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_encrypt_message_invalid_arg (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	struct cmd_interface_msg rq;
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.encrypt_message (NULL, &rq);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = cmd.session.base.encrypt_message (&cmd.session.base, NULL);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_is_session_established (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = cmd.session.base.is_session_established (&cmd.session.base, 0x10);
	CuAssertIntEquals (test, 1, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x20, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.is_session_established (&cmd.session.base, 0x20);
	CuAssertIntEquals (test, 0, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_is_session_established_unexpected_eid (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.is_session_established (&cmd.session.base, 0x30);
	CuAssertIntEquals (test, 0, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_is_session_established_invalid_arg (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.is_session_established (NULL, 0x10);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_get_pairing_state (CuTest *test)
{
	struct session_manager_ecc_testing cmd;

	uint8_t session_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t session_key2[] = {
		0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t hmac_key[] = {
		0xf1,0x3b,0x43,0x16,0xd5,0xc5,0xc6,0x10,0xad,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x37,
		0x0e,0x9a,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t pairing_key[] = {
		0xf1,0x3b,0x43,0x16,0xc6,0x10,0x34,0xd6,0x37,0xff,0x3e,0xa0,0x02,0x73,0xc5,0x54,
		0x0e,0x9a,0x2c,0xe4,0x05,0x75,0xd5,0xc5,0xad,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x41
	};
	uint8_t hmac[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,
		0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t *pairing_key_buf;
	size_t pairing_key_buf_len = sizeof (pairing_key);
	char *label_str = "pairing";
	uint8_t separator = 0;
	uint32_t i_1 = platform_htonl (1);
	uint32_t L = platform_htonl (256);
	int status;

	TEST_START;

	pairing_key_buf = platform_malloc (SHA256_HASH_LENGTH);
	CuAssertPtrNotNull (test, pairing_key_buf);

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = mock_expect (&cmd.keys_keystore.mock, cmd.keys_keystore.base.load_key,
		&cmd.keys_keystore, 0, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.keys_keystore.mock, 1, &pairing_key_buf, sizeof (uint8_t*),
		-1);
	status |= mock_expect_output (&cmd.keys_keystore.mock, 2, &pairing_key_buf_len,
		sizeof (pairing_key_buf_len), -1);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.get_pairing_state (&cmd.session.base, 0x10);
	CuAssertIntEquals (test, SESSION_PAIRING_STATE_NOT_PAIRED, status);

	status = mock_expect (&cmd.keys_keystore.mock, cmd.keys_keystore.base.load_key,
		&cmd.keys_keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, session_key, sizeof (session_key));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&i_1, sizeof (i_1)), MOCK_ARG (sizeof (i_1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (label_str, strlen (label_str)), MOCK_ARG (strlen (label_str)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&L, sizeof (L)), MOCK_ARG (sizeof (L)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, session_key, sizeof (session_key),
		NULL, SHA256_HASH_LENGTH, pairing_key, sizeof (pairing_key));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, hmac_key, sizeof (hmac_key));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (pairing_key, sizeof (pairing_key)), MOCK_ARG (sizeof (pairing_key)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, hmac_key, sizeof (hmac_key), NULL,
		SHA256_HASH_LENGTH, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, pairing_key, sizeof (pairing_key));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&i_1, sizeof (i_1)), MOCK_ARG (sizeof (i_1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&session_key, sizeof (session_key)),
		MOCK_ARG (sizeof (session_key)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&L, sizeof (L)), MOCK_ARG (sizeof (L)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, pairing_key, sizeof (pairing_key),
		NULL, SHA256_HASH_LENGTH, session_key2, sizeof (session_key2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.keys_keystore.mock, cmd.keys_keystore.base.save_key,
		&cmd.keys_keystore, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS_TMP (&pairing_key, sizeof (pairing_key)),
		MOCK_ARG (sizeof (pairing_key)));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.setup_paired_session (&cmd.session.base, 0x10, SHA256_HASH_LENGTH,
		hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	pairing_key_buf = platform_malloc (SHA256_HASH_LENGTH);
	CuAssertPtrNotNull (test, pairing_key_buf);

	status = mock_expect (&cmd.keys_keystore.mock, cmd.keys_keystore.base.load_key,
		&cmd.keys_keystore, 0, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.keys_keystore.mock, 1, &pairing_key_buf, sizeof (uint8_t*),
		-1);
	status |= mock_expect_output (&cmd.keys_keystore.mock, 2, &pairing_key_buf_len,
		sizeof (pairing_key_buf_len), -1);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.get_pairing_state (&cmd.session.base, 0x10);
	CuAssertIntEquals (test, SESSION_PAIRING_STATE_PAIRED, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_get_pairing_state_not_supported (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x12);

	status = cmd.session.base.get_pairing_state (&cmd.session.base, 0x12);
	CuAssertIntEquals (test, SESSION_PAIRING_STATE_NOT_SUPPORTED, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_get_pairing_state_no_keystore (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t *dev_id_der = NULL;
	int status;

	TEST_START;

	status = aes_mock_init (&cmd.aes);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&cmd.ecc);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&cmd.hash);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&cmd.rng);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&cmd.x509);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&cmd.riot_keystore);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&cmd.keys_keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.riot_keystore.mock, cmd.riot_keystore.base.load_key,
		&cmd.riot_keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.riot_keystore.mock, 1, &dev_id_der, sizeof (dev_id_der),
		-1);
	CuAssertIntEquals (test, 0, status);

	keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;
	keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
	keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&cmd.riot, &cmd.riot_keystore.base, &keys,
		&cmd.x509.base);
	CuAssertIntEquals (test, 0, status);

	status = session_manager_ecc_init (&cmd.session, &cmd.aes.base, &cmd.ecc.base,
		&cmd.hash.base, &cmd.rng.base, &cmd.riot, NULL, 3, PAIRING_EIDS, 2, NULL);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.get_pairing_state (&cmd.session.base, 0x10);
	CuAssertIntEquals (test, SESSION_PAIRING_STATE_NOT_SUPPORTED, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_get_pairing_state_not_initialized (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = mock_expect (&cmd.keys_keystore.mock, cmd.keys_keystore.base.load_key,
		&cmd.keys_keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.get_pairing_state (&cmd.session.base, 0x10);
	CuAssertIntEquals (test, SESSION_PAIRING_STATE_NOT_INITIALIZED, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_get_pairing_state_unexpected_eid (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t *dev_id_der = NULL;
	uint8_t *pairing_key_buf;
	size_t pairing_key_buf_len = SHA256_HASH_LENGTH;
	uint8_t pairing_eid = 0x30;
	int status;

	TEST_START;

	pairing_key_buf = platform_malloc (SHA256_HASH_LENGTH);
	CuAssertPtrNotNull (test, pairing_key_buf);

	status = aes_mock_init (&cmd.aes);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&cmd.ecc);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&cmd.hash);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&cmd.rng);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&cmd.x509);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&cmd.keys_keystore);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&cmd.riot_keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.riot_keystore.mock, cmd.riot_keystore.base.load_key,
		&cmd.riot_keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.riot_keystore.mock, 1, &dev_id_der, sizeof (dev_id_der),
		-1);
	CuAssertIntEquals (test, 0, status);

	keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;
	keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
	keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&cmd.riot, &cmd.riot_keystore.base, &keys,
		&cmd.x509.base);
	CuAssertIntEquals (test, 0, status);

	status = session_manager_ecc_init (&cmd.session, &cmd.aes.base, &cmd.ecc.base,
		&cmd.hash.base, &cmd.rng.base, &cmd.riot, NULL, 3, &pairing_eid, sizeof (pairing_eid),
		&cmd.keys_keystore.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.keys_keystore.mock, cmd.keys_keystore.base.load_key,
		&cmd.keys_keystore, 0, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.keys_keystore.mock, 1, &pairing_key_buf, sizeof (uint8_t*),
		-1);
	status |= mock_expect_output (&cmd.keys_keystore.mock, 2, &pairing_key_buf_len,
		sizeof (pairing_key_buf_len), -1);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.get_pairing_state (&cmd.session.base, 0x30);
	CuAssertIntEquals (test, SESSION_PAIRING_STATE_NOT_PAIRED, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_get_pairing_state_invalid_arg (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.get_pairing_state (NULL, 0x10);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_reset_session (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = cmd.session.base.reset_session (&cmd.session.base, 0x10, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.is_session_established (&cmd.session.base, 0x10);
	CuAssertIntEquals (test, 0, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_reset_session_paired_device (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t session_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t session_key2[] = {
		0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t hmac_key[] = {
		0xf1,0x3b,0x43,0x16,0xd5,0xc5,0xc6,0x10,0xad,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x37,
		0x0e,0x9a,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t pairing_key[] = {
		0xf1,0x3b,0x43,0x16,0xc6,0x10,0x34,0xd6,0x37,0xff,0x3e,0xa0,0x02,0x73,0xc5,0x54,
		0x0e,0x9a,0x2c,0xe4,0x05,0x75,0xd5,0xc5,0xad,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x41
	};
	uint8_t hmac[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,
		0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	char *label_str = "pairing";
	uint8_t separator = 0;
	uint32_t i_1 = platform_htonl (1);
	uint32_t L = platform_htonl (256);
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = mock_expect (&cmd.keys_keystore.mock, cmd.keys_keystore.base.load_key,
		&cmd.keys_keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, session_key, sizeof (session_key));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&i_1, sizeof (i_1)), MOCK_ARG (sizeof (i_1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (label_str, strlen (label_str)), MOCK_ARG (strlen (label_str)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&L, sizeof (L)), MOCK_ARG (sizeof (L)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, session_key, sizeof (session_key),
		NULL, SHA256_HASH_LENGTH, pairing_key, sizeof (pairing_key));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, hmac_key, sizeof (hmac_key));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (pairing_key, sizeof (pairing_key)), MOCK_ARG (sizeof (pairing_key)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, hmac_key, sizeof (hmac_key), NULL,
		SHA256_HASH_LENGTH, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, pairing_key, sizeof (pairing_key));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&i_1, sizeof (i_1)), MOCK_ARG (sizeof (i_1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&session_key, sizeof (session_key)),
		MOCK_ARG (sizeof (session_key)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&L, sizeof (L)), MOCK_ARG (sizeof (L)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, pairing_key, sizeof (pairing_key),
		NULL, SHA256_HASH_LENGTH, session_key2, sizeof (session_key2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.keys_keystore.mock, cmd.keys_keystore.base.save_key,
		&cmd.keys_keystore, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS_TMP (&pairing_key, sizeof (pairing_key)),
		MOCK_ARG (sizeof (pairing_key)));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.setup_paired_session (&cmd.session.base, 0x10, SHA256_HASH_LENGTH,
		hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.reset_session (&cmd.session.base, 0x10, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.is_session_established (&cmd.session.base, 0x10);
	CuAssertIntEquals (test, 0, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_reset_session_with_hmac (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t session_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t hmac_key[] = {
		0xf1,0x3b,0x43,0x16,0xd5,0xc5,0xc6,0x10,0xad,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x37,
		0x0e,0x9a,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t hmac[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,
		0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = hash_mock_expect_hmac_init (&cmd.hash, hmac_key, sizeof (hmac_key));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (session_key, sizeof (session_key)), MOCK_ARG (sizeof (session_key)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, hmac_key, sizeof (hmac_key), NULL,
		SHA256_HASH_LENGTH, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.reset_session (&cmd.session.base, 0x10, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.is_session_established (&cmd.session.base, 0x10);
	CuAssertIntEquals (test, 0, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_reset_session_with_hmac_session_not_established (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t hmac[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,
		0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.reset_session (&cmd.session.base, 0x10, hmac, sizeof (hmac));
	CuAssertIntEquals (test, SESSION_MANAGER_UNEXPECTED_EID, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_reset_session_with_hmac_unsupported_hmac_len (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t hmac[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,
		0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xaa
	};
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = cmd.session.base.reset_session (&cmd.session.base, 0x10, hmac, sizeof (hmac));
	CuAssertIntEquals (test, SESSION_MANAGER_OPERATION_UNSUPPORTED, status);

	status = cmd.session.base.is_session_established (&cmd.session.base, 0x10);
	CuAssertIntEquals (test, 1, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_reset_session_with_hmac_fail (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t hmac[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,
		0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash,
		HASH_ENGINE_NO_MEMORY);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.reset_session (&cmd.session.base, 0x10, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	status = cmd.session.base.is_session_established (&cmd.session.base, 0x10);
	CuAssertIntEquals (test, 1, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_reset_session_with_hmac_not_permitted (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t session_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t hmac_key[] = {
		0xf1,0x3b,0x43,0x16,0xd5,0xc5,0xc6,0x10,0xad,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x37,
		0x0e,0x9a,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t hmac[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,
		0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t hmac2[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,
		0xaa,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = hash_mock_expect_hmac_init (&cmd.hash, hmac_key, sizeof (hmac_key));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (session_key, sizeof (session_key)), MOCK_ARG (sizeof (session_key)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, hmac_key, sizeof (hmac_key), NULL,
		SHA256_HASH_LENGTH, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.reset_session (&cmd.session.base, 0x10, hmac2, sizeof (hmac2));
	CuAssertIntEquals (test, SESSION_MANAGER_OPERATION_NOT_PERMITTED, status);

	status = cmd.session.base.is_session_established (&cmd.session.base, 0x10);
	CuAssertIntEquals (test, 1, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_reset_session_unexpected_eid (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.reset_session (&cmd.session.base, 0x30, NULL, 0);
	CuAssertIntEquals (test, SESSION_MANAGER_UNEXPECTED_EID, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_reset_session_invalid_arg (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.reset_session (NULL, 0x10, NULL, 0);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_setup_paired_session (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t session_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t session_key2[] = {
		0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t hmac_key[] = {
		0xf1,0x3b,0x43,0x16,0xd5,0xc5,0xc6,0x10,0xad,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x37,
		0x0e,0x9a,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t pairing_key[] = {
		0xf1,0x3b,0x43,0x16,0xc6,0x10,0x34,0xd6,0x37,0xff,0x3e,0xa0,0x02,0x73,0xc5,0x54,
		0x0e,0x9a,0x2c,0xe4,0x05,0x75,0xd5,0xc5,0xad,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x41
	};
	uint8_t hmac[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,
		0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	char* label_str = "pairing";
	uint8_t separator = 0;
	uint32_t i_1 = platform_htonl (1);
	uint32_t L = platform_htonl (256);
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = mock_expect (&cmd.keys_keystore.mock, cmd.keys_keystore.base.load_key,
		&cmd.keys_keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, session_key, sizeof (session_key));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&i_1, sizeof (i_1)), MOCK_ARG (sizeof (i_1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (label_str, strlen (label_str)), MOCK_ARG (strlen (label_str)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&L, sizeof (L)), MOCK_ARG (sizeof (L)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, session_key, sizeof (session_key),
		NULL, SHA256_HASH_LENGTH, pairing_key, sizeof (pairing_key));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, hmac_key, sizeof (hmac_key));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (pairing_key, sizeof (pairing_key)), MOCK_ARG (sizeof (pairing_key)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, hmac_key, sizeof (hmac_key), NULL,
		SHA256_HASH_LENGTH, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, pairing_key, sizeof (pairing_key));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&i_1, sizeof (i_1)), MOCK_ARG (sizeof (i_1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&session_key, sizeof (session_key)),
		MOCK_ARG (sizeof (session_key)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&L, sizeof (L)), MOCK_ARG (sizeof (L)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, pairing_key, sizeof (pairing_key),
		NULL, SHA256_HASH_LENGTH, session_key2, sizeof (session_key2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.keys_keystore.mock, cmd.keys_keystore.base.save_key,
		&cmd.keys_keystore, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS_TMP (&pairing_key, sizeof (pairing_key)),
		MOCK_ARG (sizeof (pairing_key)));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.setup_paired_session (&cmd.session.base, 0x10, SHA256_HASH_LENGTH,
		hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_setup_paired_session_already_paired (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t session_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t session_key2[] = {
		0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t hmac_key[] = {
		0xf1,0x3b,0x43,0x16,0xd5,0xc5,0xc6,0x10,0xad,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x37,
		0x0e,0x9a,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t pairing_key[] = {
		0xf1,0x3b,0x43,0x16,0xc6,0x10,0x34,0xd6,0x37,0xff,0x3e,0xa0,0x02,0x73,0xc5,0x54,
		0x0e,0x9a,0x2c,0xe4,0x05,0x75,0xd5,0xc5,0xad,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x41
	};
	uint8_t hmac2[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,
		0x0a,0x04,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,0xd6,0x41,0x80,0xfa,0x1a,0x0e
	};
	uint8_t *pairing_key_buf;
	size_t pairing_key_buf_len = sizeof (pairing_key);
	uint8_t separator = 0;
	uint32_t i_1 = platform_htonl (1);
	uint32_t L = platform_htonl (256);
	int status;

	TEST_START;

	pairing_key_buf = platform_malloc (sizeof (pairing_key));
	CuAssertPtrNotNull (test, pairing_key_buf);

	memcpy (pairing_key_buf, pairing_key, sizeof (pairing_key));

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = mock_expect (&cmd.keys_keystore.mock, cmd.keys_keystore.base.load_key,
		&cmd.keys_keystore, 0, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.keys_keystore.mock, 1, &pairing_key_buf, sizeof (uint8_t*),
		-1);
	status |= mock_expect_output (&cmd.keys_keystore.mock, 2, &pairing_key_buf_len,
		sizeof (pairing_key_buf_len), -1);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, hmac_key, sizeof (hmac_key));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (pairing_key, sizeof (pairing_key)), MOCK_ARG (sizeof (pairing_key)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, hmac_key, sizeof (hmac_key), NULL,
		SHA256_HASH_LENGTH, hmac2, sizeof (hmac2));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, pairing_key, sizeof (pairing_key));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&i_1, sizeof (i_1)), MOCK_ARG (sizeof (i_1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&session_key, sizeof (session_key)),
		MOCK_ARG (sizeof (session_key)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&L, sizeof (L)), MOCK_ARG (sizeof (L)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, pairing_key, sizeof (pairing_key),
		NULL, SHA256_HASH_LENGTH, session_key2, sizeof (session_key2));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.setup_paired_session (&cmd.session.base, 0x10, SHA256_HASH_LENGTH,
		hmac2, sizeof (hmac2));
	CuAssertIntEquals (test, 0, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_setup_paired_session_unexpected_eid (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t hmac[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,
		0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = cmd.session.base.setup_paired_session (&cmd.session.base, 0x11, SHA256_HASH_LENGTH,
		hmac, sizeof (hmac));
	CuAssertIntEquals (test, SESSION_MANAGER_UNEXPECTED_EID, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_setup_paired_session_invalid_order (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t hmac[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,
		0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.setup_paired_session (&cmd.session.base, 0x10, SHA256_HASH_LENGTH,
		hmac, sizeof (hmac));
	CuAssertIntEquals (test, SESSION_MANAGER_UNEXPECTED_EID, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_setup_paired_session_not_permitted (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t hmac[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,
		0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x12);

	status = cmd.session.base.setup_paired_session (&cmd.session.base, 0x12, SHA256_HASH_LENGTH,
		hmac, sizeof (hmac));
	CuAssertIntEquals (test, SESSION_MANAGER_PAIRING_NOT_SUPPORTED_WITH_DEVICE, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_setup_paired_session_load_pairing_key_fail (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t hmac2[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,
		0x0a,0x04,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,0xd6,0x41,0x80,0xfa,0x1a,0x0e
	};
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = mock_expect (&cmd.keys_keystore.mock, cmd.keys_keystore.base.load_key,
		&cmd.keys_keystore, KEYSTORE_NO_MEMORY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.setup_paired_session (&cmd.session.base, 0x10, SHA256_HASH_LENGTH,
		hmac2, sizeof (hmac2));
	CuAssertIntEquals (test, KEYSTORE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_setup_paired_session_generate_pairing_key_fail (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t hmac[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,
		0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = mock_expect (&cmd.keys_keystore.mock, cmd.keys_keystore.base.load_key,
		&cmd.keys_keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash,
		HASH_ENGINE_NO_MEMORY);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.setup_paired_session (&cmd.session.base, 0x10, SHA256_HASH_LENGTH,
		hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_setup_paired_session_generate_hmac_init_fail (
	CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t session_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t pairing_key[] = {
		0xf1,0x3b,0x43,0x16,0xc6,0x10,0x34,0xd6,0x37,0xff,0x3e,0xa0,0x02,0x73,0xc5,0x54,
		0x0e,0x9a,0x2c,0xe4,0x05,0x75,0xd5,0xc5,0xad,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x41
	};
	uint8_t hmac[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,
		0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	char* label_str = "pairing";
	uint8_t separator = 0;
	uint32_t i_1 = platform_htonl (1);
	uint32_t L = platform_htonl (256);
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = mock_expect (&cmd.keys_keystore.mock, cmd.keys_keystore.base.load_key,
		&cmd.keys_keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, session_key, sizeof (session_key));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&i_1, sizeof (i_1)), MOCK_ARG (sizeof (i_1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (label_str, strlen (label_str)), MOCK_ARG (strlen (label_str)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&L, sizeof (L)), MOCK_ARG (sizeof (L)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, session_key, sizeof (session_key),
		NULL, SHA256_HASH_LENGTH, pairing_key, sizeof (pairing_key));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash,
		HASH_ENGINE_NO_MEMORY);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.setup_paired_session (&cmd.session.base, 0x10, SHA256_HASH_LENGTH,
		hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_setup_paired_session_generate_hmac_update_fail (
	CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t session_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t hmac_key[] = {
		0xf1,0x3b,0x43,0x16,0xd5,0xc5,0xc6,0x10,0xad,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x37,
		0x0e,0x9a,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t pairing_key[] = {
		0xf1,0x3b,0x43,0x16,0xc6,0x10,0x34,0xd6,0x37,0xff,0x3e,0xa0,0x02,0x73,0xc5,0x54,
		0x0e,0x9a,0x2c,0xe4,0x05,0x75,0xd5,0xc5,0xad,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x41
	};
	uint8_t hmac[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,
		0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	char* label_str = "pairing";
	uint8_t separator = 0;
	uint32_t i_1 = platform_htonl (1);
	uint32_t L = platform_htonl (256);
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = mock_expect (&cmd.keys_keystore.mock, cmd.keys_keystore.base.load_key,
		&cmd.keys_keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, session_key, sizeof (session_key));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&i_1, sizeof (i_1)), MOCK_ARG (sizeof (i_1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (label_str, strlen (label_str)), MOCK_ARG (strlen (label_str)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&L, sizeof (L)), MOCK_ARG (sizeof (L)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, session_key, sizeof (session_key),
		NULL, SHA256_HASH_LENGTH, pairing_key, sizeof (pairing_key));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, hmac_key, sizeof (hmac_key));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, HASH_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS (pairing_key, sizeof (pairing_key)), MOCK_ARG (sizeof (pairing_key)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.cancel, &cmd.hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.setup_paired_session (&cmd.session.base, 0x10, SHA256_HASH_LENGTH,
		hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_setup_paired_session_generate_hmac_finish_fail (
	CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t session_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t hmac_key[] = {
		0xf1,0x3b,0x43,0x16,0xd5,0xc5,0xc6,0x10,0xad,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x37,
		0x0e,0x9a,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t pairing_key[] = {
		0xf1,0x3b,0x43,0x16,0xc6,0x10,0x34,0xd6,0x37,0xff,0x3e,0xa0,0x02,0x73,0xc5,0x54,
		0x0e,0x9a,0x2c,0xe4,0x05,0x75,0xd5,0xc5,0xad,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x41
	};
	uint8_t hmac[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,
		0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	char* label_str = "pairing";
	uint8_t separator = 0;
	uint32_t i_1 = platform_htonl (1);
	uint32_t L = platform_htonl (256);
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = mock_expect (&cmd.keys_keystore.mock, cmd.keys_keystore.base.load_key,
		&cmd.keys_keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, session_key, sizeof (session_key));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&i_1, sizeof (i_1)), MOCK_ARG (sizeof (i_1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (label_str, strlen (label_str)), MOCK_ARG (strlen (label_str)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&L, sizeof (L)), MOCK_ARG (sizeof (L)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, session_key, sizeof (session_key),
		NULL, SHA256_HASH_LENGTH, pairing_key, sizeof (pairing_key));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, hmac_key, sizeof (hmac_key));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (pairing_key, sizeof (pairing_key)), MOCK_ARG (sizeof (pairing_key)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.finish, &cmd.hash, HASH_ENGINE_NO_MEMORY,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.cancel, &cmd.hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.setup_paired_session (&cmd.session.base, 0x10, SHA256_HASH_LENGTH,
		hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_setup_paired_session_generate_session_key_fail (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t session_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t hmac_key[] = {
		0xf1,0x3b,0x43,0x16,0xd5,0xc5,0xc6,0x10,0xad,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x37,
		0x0e,0x9a,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t pairing_key[] = {
		0xf1,0x3b,0x43,0x16,0xc6,0x10,0x34,0xd6,0x37,0xff,0x3e,0xa0,0x02,0x73,0xc5,0x54,
		0x0e,0x9a,0x2c,0xe4,0x05,0x75,0xd5,0xc5,0xad,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x41
	};
	uint8_t hmac[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,
		0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	char* label_str = "pairing";
	uint8_t separator = 0;
	uint32_t i_1 = platform_htonl (1);
	uint32_t L = platform_htonl (256);
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = mock_expect (&cmd.keys_keystore.mock, cmd.keys_keystore.base.load_key,
		&cmd.keys_keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, session_key, sizeof (session_key));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&i_1, sizeof (i_1)), MOCK_ARG (sizeof (i_1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (label_str, strlen (label_str)), MOCK_ARG (strlen (label_str)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&L, sizeof (L)), MOCK_ARG (sizeof (L)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, session_key, sizeof (session_key),
		NULL, SHA256_HASH_LENGTH, pairing_key, sizeof (pairing_key));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, hmac_key, sizeof (hmac_key));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (pairing_key, sizeof (pairing_key)), MOCK_ARG (sizeof (pairing_key)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, hmac_key, sizeof (hmac_key), NULL,
		SHA256_HASH_LENGTH, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash,
		HASH_ENGINE_NO_MEMORY);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.setup_paired_session (&cmd.session.base, 0x10, SHA256_HASH_LENGTH,
		hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_setup_paired_session_save_pairing_key_fail (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t session_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t session_key2[] = {
		0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t hmac_key[] = {
		0xf1,0x3b,0x43,0x16,0xd5,0xc5,0xc6,0x10,0xad,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x37,
		0x0e,0x9a,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t pairing_key[] = {
		0xf1,0x3b,0x43,0x16,0xc6,0x10,0x34,0xd6,0x37,0xff,0x3e,0xa0,0x02,0x73,0xc5,0x54,
		0x0e,0x9a,0x2c,0xe4,0x05,0x75,0xd5,0xc5,0xad,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x41
	};
	uint8_t hmac[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,
		0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	char* label_str = "pairing";
	uint8_t separator = 0;
	uint32_t i_1 = platform_htonl (1);
	uint32_t L = platform_htonl (256);
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = mock_expect (&cmd.keys_keystore.mock, cmd.keys_keystore.base.load_key,
		&cmd.keys_keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, session_key, sizeof (session_key));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&i_1, sizeof (i_1)), MOCK_ARG (sizeof (i_1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (label_str, strlen (label_str)), MOCK_ARG (strlen (label_str)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&L, sizeof (L)), MOCK_ARG (sizeof (L)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, session_key, sizeof (session_key),
		NULL, SHA256_HASH_LENGTH, pairing_key, sizeof (pairing_key));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, hmac_key, sizeof (hmac_key));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (pairing_key, sizeof (pairing_key)), MOCK_ARG (sizeof (pairing_key)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, hmac_key, sizeof (hmac_key), NULL,
		SHA256_HASH_LENGTH, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, pairing_key, sizeof (pairing_key));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&i_1, sizeof (i_1)), MOCK_ARG (sizeof (i_1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&session_key, sizeof (session_key)),
		MOCK_ARG (sizeof (session_key)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&L, sizeof (L)), MOCK_ARG (sizeof (L)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, pairing_key, sizeof (pairing_key),
		NULL, SHA256_HASH_LENGTH, session_key2, sizeof (session_key2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.keys_keystore.mock, cmd.keys_keystore.base.save_key,
		&cmd.keys_keystore, KEYSTORE_NO_MEMORY, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS_TMP (&pairing_key, sizeof (pairing_key)),
		MOCK_ARG (sizeof (pairing_key)));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.setup_paired_session (&cmd.session.base, 0x10, SHA256_HASH_LENGTH,
		hmac, sizeof (hmac));
	CuAssertIntEquals (test, KEYSTORE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_setup_paired_session_unsupported (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t hmac[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,
		0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t *dev_id_der = NULL;
	int status;

	TEST_START;

	status = aes_mock_init (&cmd.aes);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&cmd.ecc);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&cmd.hash);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&cmd.rng);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&cmd.x509);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&cmd.riot_keystore);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&cmd.keys_keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.riot_keystore.mock, cmd.riot_keystore.base.load_key,
		&cmd.riot_keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.riot_keystore.mock, 1, &dev_id_der, sizeof (dev_id_der),
		-1);
	CuAssertIntEquals (test, 0, status);

	keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;
	keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
	keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&cmd.riot, &cmd.riot_keystore.base, &keys,
		&cmd.x509.base);
	CuAssertIntEquals (test, 0, status);

	status = session_manager_ecc_init (&cmd.session, &cmd.aes.base, &cmd.ecc.base,
		&cmd.hash.base, &cmd.rng.base, &cmd.riot, NULL, 3, NULL, 1, NULL);
	CuAssertIntEquals (test, 0, status);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = cmd.session.base.setup_paired_session (&cmd.session.base, 0x10, SHA256_HASH_LENGTH,
		hmac, sizeof (hmac));
	CuAssertIntEquals (test, SESSION_MANAGER_OPERATION_UNSUPPORTED, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_setup_paired_session_invalid_arg (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t hmac[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,
		0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.setup_paired_session (NULL, 0x10, SHA256_HASH_LENGTH,
		hmac, sizeof (hmac));
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = cmd.session.base.setup_paired_session (&cmd.session.base, 0x10, SHA256_HASH_LENGTH,
		NULL, sizeof (hmac));
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_session_sync (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t hmac[SHA256_HASH_LENGTH];
	uint8_t hmac_expected[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,
		0xd6,0x41,0x20,0xfa,0x1a,0x0e,0x0a,0x04,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint32_t rn_req = 0xaabbccdd;
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = hash_mock_expect_hmac (&cmd.hash, HMAC_KEY, sizeof (HMAC_KEY),
		(const uint8_t*) &rn_req, sizeof (rn_req), NULL, sizeof (hmac), hmac_expected,
		sizeof (hmac_expected));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.session_sync (&cmd.session.base, 0x10, rn_req, hmac, sizeof (hmac));
	CuAssertIntEquals (test, sizeof (hmac_expected), status);

	status = testing_validate_array (hmac_expected, hmac, sizeof (hmac_expected));
	CuAssertIntEquals (test, 0, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_session_sync_unexpected_eid (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t hmac[SHA256_HASH_LENGTH];
	uint32_t rn_req = 0xaabbccdd;
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = cmd.session.base.session_sync (&cmd.session.base, 0x11, rn_req, hmac, sizeof (hmac));
	CuAssertIntEquals (test, SESSION_MANAGER_UNEXPECTED_EID, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_session_sync_session_not_established (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t hmac[SHA256_HASH_LENGTH];
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint32_t rn_req = 0xaabbccdd;
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.session_sync (&cmd.session.base, 0x10, rn_req, hmac, sizeof (hmac));
	CuAssertIntEquals (test, SESSION_MANAGER_SESSION_NOT_ESTABLISHED, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_session_sync_generate_hmac_fail (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t hmac[SHA256_HASH_LENGTH];
	uint32_t rn_req = 0xaabbccdd;
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash,
		HASH_ENGINE_NO_MEMORY);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.session_sync (&cmd.session.base, 0x10, rn_req, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_session_sync_invalid_arg (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t hmac[SHA256_HASH_LENGTH];
	uint32_t rn_req = 0xaabbccdd;
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	session_manager_ecc_establish_session (test, &cmd, 0x10);

	status = cmd.session.base.session_sync (NULL, 0x11, rn_req, hmac, sizeof (hmac));
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = cmd.session.base.session_sync (&cmd.session.base, 0x11, rn_req, NULL, sizeof (hmac));
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	release_session_manager_ecc_test (test, &cmd);
}


TEST_SUITE_START (session_manager_ecc);

TEST (session_manager_ecc_test_init);
TEST (session_manager_ecc_test_init_preallocated_table);
TEST (session_manager_ecc_test_init_invalid_arg);
TEST (session_manager_ecc_test_release_null);
TEST (session_manager_ecc_test_add_session);
TEST (session_manager_ecc_test_add_session_restart);
TEST (session_manager_ecc_test_add_session_full);
TEST (session_manager_ecc_test_add_session_invalid_arg);
TEST (session_manager_ecc_test_establish_session);
TEST (session_manager_ecc_test_establish_session_invalid_request);
TEST (session_manager_ecc_test_establish_session_buf_smaller_than_response);
TEST (session_manager_ecc_test_establish_session_invalid_order);
TEST (session_manager_ecc_test_establish_session_unexpected_eid);
TEST (session_manager_ecc_test_establish_session_unsupported_hash_type);
TEST (session_manager_ecc_test_establish_session_init_device_pub_key_fail);
TEST (session_manager_ecc_test_establish_session_generate_response_key_fail);
TEST (session_manager_ecc_test_establish_session_get_session_key_der_fail);
TEST (session_manager_ecc_test_establish_session_start_keys_digest_fail);
TEST (session_manager_ecc_test_establish_session_update_keys_digest_device_key_fail);
TEST (session_manager_ecc_test_establish_session_update_keys_digest_session_key_fail);
TEST (session_manager_ecc_test_establish_session_finish_keys_digest_fail);
TEST (session_manager_ecc_test_establish_session_buf_smaller_than_session_key);
TEST (session_manager_ecc_test_establish_session_init_alias_priv_key_fail);
TEST (session_manager_ecc_test_establish_session_get_max_sig_len_fail);
TEST (session_manager_ecc_test_establish_session_sign_fail);
TEST (session_manager_ecc_test_establish_session_size_shared_secret_fail);
TEST (session_manager_ecc_test_establish_session_compute_shared_secret_fail);
TEST (session_manager_ecc_test_establish_session_generate_session_key_fail);
TEST (session_manager_ecc_test_establish_session_generate_hmac_key_fail);
TEST (session_manager_ecc_test_establish_session_generate_hmac_fail);
TEST (session_manager_ecc_test_establish_session_invalid_arg);
TEST (session_manager_ecc_test_decrypt_message);
TEST (session_manager_ecc_test_decrypt_message_unexpected_eid);
TEST (session_manager_ecc_test_decrypt_message_session_not_established);
TEST (session_manager_ecc_test_decrypt_message_set_key_fail);
TEST (session_manager_ecc_test_decrypt_message_fail);
TEST (session_manager_ecc_test_decrypt_message_invalid_message);
TEST (session_manager_ecc_test_decrypt_message_buf_too_small);
TEST (session_manager_ecc_test_decrypt_message_invalid_arg);
TEST (session_manager_ecc_test_encrypt_message);
TEST (session_manager_ecc_test_encrypt_message_unexpected_eid);
TEST (session_manager_ecc_test_encrypt_message_session_not_established);
TEST (session_manager_ecc_test_encrypt_message_set_key_fail);
TEST (session_manager_ecc_test_encrypt_message_generate_iv_fail);
TEST (session_manager_ecc_test_encrypt_message_fail);
TEST (session_manager_ecc_test_encrypt_message_no_payload);
TEST (session_manager_ecc_test_encrypt_message_buf_too_small);
TEST (session_manager_ecc_test_encrypt_message_invalid_arg);
TEST (session_manager_ecc_test_is_session_established);
TEST (session_manager_ecc_test_is_session_established_unexpected_eid);
TEST (session_manager_ecc_test_is_session_established_invalid_arg);
TEST (session_manager_ecc_test_get_pairing_state);
TEST (session_manager_ecc_test_get_pairing_state_not_supported);
TEST (session_manager_ecc_test_get_pairing_state_no_keystore);
TEST (session_manager_ecc_test_get_pairing_state_not_initialized);
TEST (session_manager_ecc_test_get_pairing_state_unexpected_eid);
TEST (session_manager_ecc_test_get_pairing_state_invalid_arg);
TEST (session_manager_ecc_test_reset_session);
TEST (session_manager_ecc_test_reset_session_paired_device);
TEST (session_manager_ecc_test_reset_session_with_hmac);
TEST (session_manager_ecc_test_reset_session_with_hmac_session_not_established);
TEST (session_manager_ecc_test_reset_session_with_hmac_unsupported_hmac_len);
TEST (session_manager_ecc_test_reset_session_with_hmac_fail);
TEST (session_manager_ecc_test_reset_session_with_hmac_not_permitted);
TEST (session_manager_ecc_test_reset_session_unexpected_eid);
TEST (session_manager_ecc_test_reset_session_invalid_arg);
TEST (session_manager_ecc_test_setup_paired_session);
TEST (session_manager_ecc_test_setup_paired_session_already_paired);
TEST (session_manager_ecc_test_setup_paired_session_unexpected_eid);
TEST (session_manager_ecc_test_setup_paired_session_invalid_order);
TEST (session_manager_ecc_test_setup_paired_session_not_permitted);
TEST (session_manager_ecc_test_setup_paired_session_load_pairing_key_fail);
TEST (session_manager_ecc_test_setup_paired_session_generate_pairing_key_fail);
TEST (session_manager_ecc_test_setup_paired_session_generate_hmac_init_fail);
TEST (session_manager_ecc_test_setup_paired_session_generate_hmac_update_fail);
TEST (session_manager_ecc_test_setup_paired_session_generate_hmac_finish_fail);
TEST (session_manager_ecc_test_setup_paired_session_generate_session_key_fail);
TEST (session_manager_ecc_test_setup_paired_session_save_pairing_key_fail);
TEST (session_manager_ecc_test_setup_paired_session_unsupported);
TEST (session_manager_ecc_test_setup_paired_session_invalid_arg);
TEST (session_manager_ecc_test_session_sync);
TEST (session_manager_ecc_test_session_sync_unexpected_eid);
TEST (session_manager_ecc_test_session_sync_session_not_established);
TEST (session_manager_ecc_test_session_sync_generate_hmac_fail);
TEST (session_manager_ecc_test_session_sync_invalid_arg);

TEST_SUITE_END;
