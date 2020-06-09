// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "platform.h"
#include "testing.h"
#include "ecc_testing.h"
#include "mock/aes_mock.h"
#include "mock/ecc_mock.h"
#include "mock/hash_mock.h"
#include "mock/rng_mock.h"
#include "mock/x509_mock.h"
#include "mock/keystore_mock.h"
#include "cmd_interface/session_manager_ecc.h"
#include "testing/ecc_testing.h"
#include "testing/riot_core_testing.h"


static const char *SUITE = "session_manager_ecc";


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

const static uint8_t SHARED_SECRET[] = {
	0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7, 
	0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,
	0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,
	0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7
};

const static uint8_t SESSION_AES_IV[] = {
	0xaa,0xee,0xff,0x11,0x44,0xdd,0x77,0xcc,0x22,0xaa,0xdd,0xff
};

const static uint8_t SESSION_AES_GCM_TAG[] = {
	0x77,0x0e,0x72,0x2a,0x01,0xf8,0xfb,0xf6,0x26,0x1d,0x78,0xec,0x83,0xff,0xcf,0x4c
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
		&cmd->hash.base, &cmd->rng.base, &cmd->riot, 3);
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

	status = keystore_mock_validate_and_release (&cmd->riot_keystore);
	CuAssertIntEquals (test, 0, status);

	riot_key_manager_release (&cmd->riot);

	session_manager_ecc_release (&cmd->session);
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
		&cmd.rng.base, &cmd.riot, 1);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cmd.session.base.add_session);
	CuAssertPtrNotNull (test, cmd.session.base.establish_session);
	CuAssertPtrNotNull (test, cmd.session.base.is_session_established);
	CuAssertPtrNotNull (test, cmd.session.base.decrypt_message);
	CuAssertPtrNotNull (test, cmd.session.base.encrypt_message);

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

	status = session_manager_ecc_init (NULL, &cmd.aes.base, &cmd.ecc.base, &cmd.hash.base, 
		&cmd.rng.base, &cmd.riot, 1);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = session_manager_ecc_init (&cmd.session, NULL, &cmd.ecc.base, &cmd.hash.base, 
		&cmd.rng.base, &cmd.riot, 1);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = session_manager_ecc_init (&cmd.session, &cmd.aes.base, NULL, &cmd.hash.base, 
		&cmd.rng.base, &cmd.riot, 1);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = session_manager_ecc_init (&cmd.session, &cmd.aes.base, &cmd.ecc.base, NULL, 
		&cmd.rng.base, &cmd.riot, 1);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = session_manager_ecc_init (&cmd.session, &cmd.aes.base, &cmd.ecc.base, &cmd.hash.base, 
		NULL, &cmd.riot, 1);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = session_manager_ecc_init (&cmd.session, &cmd.aes.base, &cmd.ecc.base, &cmd.hash.base, 
		&cmd.rng.base, NULL, 1);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = aes_mock_validate_and_release (&cmd.aes);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&cmd.ecc);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&cmd.hash);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&cmd.rng);
	CuAssertIntEquals (test, 0, status);
}

static void session_manager_ecc_test_init_preallocated_table (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	struct session_manager_ecc_entry sessions_table[2];
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

	status = session_manager_ecc_init_table_preallocated (&cmd.session, &cmd.aes.base, 
		&cmd.ecc.base, &cmd.hash.base, &cmd.rng.base, &cmd.riot, sessions_table, 1);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cmd.session.base.add_session);
	CuAssertPtrNotNull (test, cmd.session.base.establish_session);
	CuAssertPtrNotNull (test, cmd.session.base.is_session_established);
	CuAssertPtrNotNull (test, cmd.session.base.decrypt_message);
	CuAssertPtrNotNull (test, cmd.session.base.encrypt_message);

	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_init_preallocated_table_invalid_arg (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	struct session_manager_ecc_entry sessions_table[2];
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

	status = session_manager_ecc_init_table_preallocated (NULL, &cmd.aes.base, &cmd.ecc.base, 
		&cmd.hash.base, &cmd.rng.base, &cmd.riot, sessions_table, 1);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = session_manager_ecc_init_table_preallocated (&cmd.session, NULL, &cmd.ecc.base, 
		&cmd.hash.base, &cmd.rng.base, &cmd.riot, sessions_table, 1);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = session_manager_ecc_init_table_preallocated (&cmd.session, &cmd.aes.base, NULL, 
		&cmd.hash.base, &cmd.rng.base, &cmd.riot, sessions_table, 1);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = session_manager_ecc_init_table_preallocated (&cmd.session, &cmd.aes.base, 
		&cmd.ecc.base, NULL, &cmd.rng.base, &cmd.riot, sessions_table, 1);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = session_manager_ecc_init_table_preallocated (&cmd.session, &cmd.aes.base, 
		&cmd.ecc.base, &cmd.hash.base, NULL, &cmd.riot, sessions_table, 1);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = session_manager_ecc_init_table_preallocated (&cmd.session, &cmd.aes.base, 
		&cmd.ecc.base, &cmd.hash.base, &cmd.rng.base, NULL, sessions_table, 1);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = session_manager_ecc_init_table_preallocated (&cmd.session, &cmd.aes.base, 
		&cmd.ecc.base, &cmd.hash.base, &cmd.rng.base, &cmd.riot, NULL, 1);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = aes_mock_validate_and_release (&cmd.aes);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&cmd.ecc);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&cmd.hash);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&cmd.rng);
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
	uint8_t nonce1[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t aes_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.compute_shared_secret, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&cmd.ecc.mock, 2, SHARED_SECRET, sizeof (SHARED_SECRET), 3);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce1, sizeof (nonce1)), MOCK_ARG (sizeof (nonce1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce2, sizeof (nonce2)), MOCK_ARG (sizeof (nonce2)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET), 
		NULL, SHA256_HASH_LENGTH, aes_key, sizeof (aes_key));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x10, ECC_PUBKEY_DER, 
		ECC_PUBKEY_DER_LEN, true);
	CuAssertIntEquals (test, 0, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_paired (CuTest *test)
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
	uint8_t nonce3[] = {
		0xf1,0xdd,0xaa,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0xbb,0xcc,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t nonce4[] = {
		0x0e,0xbb,0xcc,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0xf1,0xdd,0xaa,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t aes_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t aes_key2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.compute_shared_secret, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&cmd.ecc.mock, 2, SHARED_SECRET, sizeof (SHARED_SECRET), 3);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce1, sizeof (nonce1)), MOCK_ARG (sizeof (nonce1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce2, sizeof (nonce2)), MOCK_ARG (sizeof (nonce2)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET), 
		NULL, SHA256_HASH_LENGTH, aes_key, sizeof (aes_key));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x10, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.is_session_established (&cmd.session.base, 0x10);
	CuAssertIntEquals (test, 1, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 3);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.compute_shared_secret, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (2), MOCK_ARG_SAVED_ARG (3), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&cmd.ecc.mock, 2, SHARED_SECRET, sizeof (SHARED_SECRET), 3);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce3, sizeof (nonce3)), MOCK_ARG (sizeof (nonce3)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce4, sizeof (nonce4)), MOCK_ARG (sizeof (nonce4)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET), 
		NULL, SHA256_HASH_LENGTH, aes_key2, sizeof (aes_key2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (2), MOCK_ARG_SAVED_ARG (3));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce3, nonce4);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x10, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, true);
	CuAssertIntEquals (test, 0, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_replace (CuTest *test)
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
	uint8_t nonce3[] = {
		0xf1,0xdd,0xaa,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0xbb,0xcc,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t nonce4[] = {
		0x0e,0xbb,0xcc,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0xf1,0xdd,0xaa,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t aes_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t aes_key2[] = {
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.compute_shared_secret, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&cmd.ecc.mock, 2, SHARED_SECRET, sizeof (SHARED_SECRET), 3);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce1, sizeof (nonce1)), MOCK_ARG (sizeof (nonce1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce2, sizeof (nonce2)), MOCK_ARG (sizeof (nonce2)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET), 
		NULL, SHA256_HASH_LENGTH, aes_key, sizeof (aes_key));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x10, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.is_session_established (&cmd.session.base, 0x10);
	CuAssertIntEquals (test, 1, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN),
		MOCK_ARG (ECC_PUBKEY2_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 3);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.compute_shared_secret, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (2), MOCK_ARG_SAVED_ARG (3), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&cmd.ecc.mock, 2, SHARED_SECRET, sizeof (SHARED_SECRET), 3);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce3, sizeof (nonce3)), MOCK_ARG (sizeof (nonce3)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce4, sizeof (nonce4)), MOCK_ARG (sizeof (nonce4)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET), 
		NULL, SHA256_HASH_LENGTH, aes_key2, sizeof (aes_key2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (2), MOCK_ARG_SAVED_ARG (3));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce3, nonce4);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x10, ECC_PUBKEY2_DER,
		ECC_PUBKEY2_DER_LEN, false);
	CuAssertIntEquals (test, 0, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_paired_unexpected_key (CuTest *test)
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
	uint8_t nonce3[] = {
		0x0e,0xbb,0xcc,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0xf1,0xdd,0xaa,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t nonce4[] = {
		0xf1,0xdd,0xaa,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0xbb,0xcc,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t aes_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.compute_shared_secret, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&cmd.ecc.mock, 2, SHARED_SECRET, sizeof (SHARED_SECRET), 3);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce1, sizeof (nonce1)), MOCK_ARG (sizeof (nonce1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce2, sizeof (nonce2)), MOCK_ARG (sizeof (nonce2)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET), 
		NULL, SHA256_HASH_LENGTH, aes_key, sizeof (aes_key));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x10, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.is_session_established (&cmd.session.base, 0x10);
	CuAssertIntEquals (test, 1, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce3, nonce4);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x10, ECC_PUBKEY2_DER, 
		ECC_PUBKEY2_DER_LEN, true);
	CuAssertIntEquals (test, SESSION_MANAGER_UNEXPECTED_PUBKEY, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_invalid_order (CuTest *test)
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
	uint8_t aes_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.compute_shared_secret, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&cmd.ecc.mock, 2, SHARED_SECRET, sizeof (SHARED_SECRET), 3);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce1, sizeof (nonce1)), MOCK_ARG (sizeof (nonce1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce2, sizeof (nonce2)), MOCK_ARG (sizeof (nonce2)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET), 
		NULL, SHA256_HASH_LENGTH, aes_key, sizeof (aes_key));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x10, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.is_session_established (&cmd.session.base, 0x10);
	CuAssertIntEquals (test, 1, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x10, ECC_PUBKEY2_DER,
		ECC_PUBKEY2_DER_LEN, false);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ORDER, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_unexpected_eid (CuTest *test)
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

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x11, ECC_PUBKEY_DER, 
		ECC_PUBKEY_DER_LEN, true);
	CuAssertIntEquals (test, SESSION_MANAGER_UNEXPECTED_EID, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_init_priv_key_fail (CuTest *test)
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

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, ECC_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x10, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, true);
	CuAssertIntEquals (test, ECC_ENGINE_NO_MEMORY, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_init_pub_key_fail (CuTest *test)
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

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 
		ECC_ENGINE_NO_MEMORY, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x10, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, true);
	CuAssertIntEquals (test, ECC_ENGINE_NO_MEMORY, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_size_shared_secret_fail (CuTest *test)
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

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc, 
		ECC_ENGINE_NO_MEMORY, MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x10, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, true);
	CuAssertIntEquals (test, ECC_ENGINE_NO_MEMORY, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_compute_shared_secret_fail (CuTest *test)
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

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.compute_shared_secret, &cmd.ecc, 
		ECC_ENGINE_NO_MEMORY, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, 
		MOCK_ARG (64));
	status |= mock_expect_output (&cmd.ecc.mock, 2, SHARED_SECRET, sizeof (SHARED_SECRET), 3);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x10, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, true);
	CuAssertIntEquals (test, ECC_ENGINE_NO_MEMORY, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_init_hmac_fail (CuTest *test)
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

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.compute_shared_secret, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&cmd.ecc.mock, 2, SHARED_SECRET, sizeof (SHARED_SECRET), 3);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash, 
		HASH_ENGINE_NO_MEMORY);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x10, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, true);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_update1_hmac_fail (CuTest *test)
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

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.compute_shared_secret, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&cmd.ecc.mock, 2, SHARED_SECRET, sizeof (SHARED_SECRET), 3);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, HASH_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS (&nonce1, sizeof (nonce1)), MOCK_ARG (sizeof (nonce1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.cancel, &cmd.hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x10, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, true);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_update2_hmac_fail (CuTest *test)
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

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.compute_shared_secret, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&cmd.ecc.mock, 2, SHARED_SECRET, sizeof (SHARED_SECRET), 3);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce1, sizeof (nonce1)), MOCK_ARG (sizeof (nonce1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, HASH_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS (&nonce2, sizeof (nonce2)), MOCK_ARG (sizeof (nonce2)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.cancel, &cmd.hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x10, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, true);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_finish_hmac_fail (CuTest *test)
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

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.compute_shared_secret, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&cmd.ecc.mock, 2, SHARED_SECRET, sizeof (SHARED_SECRET), 3);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce1, sizeof (nonce1)), MOCK_ARG (sizeof (nonce1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce2, sizeof (nonce2)), MOCK_ARG (sizeof (nonce2)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.finish, &cmd.hash, HASH_ENGINE_NO_MEMORY, 
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.cancel, &cmd.hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x10, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, true);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_establish_session_invalid_arg (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.establish_session (NULL, 0x10, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, true);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x10, NULL, ECC_PUBKEY_DER_LEN, true);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_decrypt_message (CuTest *test)
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
	uint8_t data[] = {0xA, 0xB, 0xC, 0xD, 0xE};
	uint8_t decrypted[] = {0x1, 0x2, 0x3, 0x4, 0x5};
	uint8_t aes_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t msg[33];
	int status;

	TEST_START;

	memcpy (msg, data, sizeof (data));
	memcpy (&msg[sizeof (data)], SESSION_AES_GCM_TAG, sizeof (SESSION_AES_GCM_TAG));
	memcpy (&msg[sizeof (data) + sizeof (SESSION_AES_GCM_TAG)], SESSION_AES_IV, 
		sizeof (SESSION_AES_IV));

	setup_session_manager_ecc_test (test, &cmd);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.compute_shared_secret, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&cmd.ecc.mock, 2, SHARED_SECRET, sizeof (SHARED_SECRET), 3);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce1, sizeof (nonce1)), MOCK_ARG (sizeof (nonce1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce2, sizeof (nonce2)), MOCK_ARG (sizeof (nonce2)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET), 
		NULL, SHA256_HASH_LENGTH, aes_key, sizeof (aes_key));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x10, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.aes.mock, cmd.aes.base.set_key, &cmd.aes, 0, 
		MOCK_ARG_PTR_CONTAINS_TMP (aes_key, sizeof (aes_key)), MOCK_ARG (sizeof (aes_key)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.aes.mock, cmd.aes.base.decrypt_data, &cmd.aes, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (msg, sizeof (data)), MOCK_ARG (sizeof (data)), 
		MOCK_ARG_PTR_CONTAINS (SESSION_AES_GCM_TAG, sizeof (SESSION_AES_GCM_TAG)), 
		MOCK_ARG_PTR_CONTAINS (SESSION_AES_IV, sizeof (SESSION_AES_IV)), 
		MOCK_ARG (sizeof (SESSION_AES_IV)), MOCK_ARG_NOT_NULL, 
		MOCK_ARG (sizeof (msg)));
	status |= mock_expect_output (&cmd.aes.mock, 5, decrypted, sizeof (decrypted), 6);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.decrypt_message (&cmd.session.base, 0x10, msg, sizeof (msg), 
		sizeof (msg));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (decrypted, msg, sizeof (decrypted));
	CuAssertIntEquals (test, 0, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_decrypt_message_unexpected_eid (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t msg[33];
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.decrypt_message (&cmd.session.base, 0x11, msg, sizeof (msg), 
		sizeof (msg));
	CuAssertIntEquals (test, SESSION_MANAGER_UNEXPECTED_EID, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_decrypt_message_session_not_established (CuTest *test)
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
	uint8_t msg[33];
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.decrypt_message (&cmd.session.base, 0x10, msg, sizeof (msg), 
		sizeof (msg));
	CuAssertIntEquals (test, SESSION_MANAGER_SESSION_NOT_ESTABLISHED, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_decrypt_message_set_key_fail (CuTest *test)
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
	uint8_t aes_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t msg[33];
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.compute_shared_secret, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&cmd.ecc.mock, 2, SHARED_SECRET, sizeof (SHARED_SECRET), 3);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce1, sizeof (nonce1)), MOCK_ARG (sizeof (nonce1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce2, sizeof (nonce2)), MOCK_ARG (sizeof (nonce2)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET), 
		NULL, SHA256_HASH_LENGTH, aes_key, sizeof (aes_key));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x10, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.aes.mock, cmd.aes.base.set_key, &cmd.aes, AES_ENGINE_NO_MEMORY, 
		MOCK_ARG_PTR_CONTAINS_TMP (aes_key, sizeof (aes_key)), MOCK_ARG (sizeof (aes_key)));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.decrypt_message (&cmd.session.base, 0x10, msg, sizeof (msg), 
		sizeof (msg));
	CuAssertIntEquals (test, AES_ENGINE_NO_MEMORY, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_decrypt_message_fail (CuTest *test)
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
	uint8_t data[] = {
		0xA,0xB,0xC,0xD,0xE
	};
	uint8_t aes_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	uint8_t msg[33];
	int status;

	TEST_START;

	memcpy (msg, data, sizeof (data));
	memcpy (&msg[sizeof (data)], SESSION_AES_GCM_TAG, sizeof (SESSION_AES_GCM_TAG));
	memcpy (&msg[sizeof (data) + sizeof (SESSION_AES_GCM_TAG)], SESSION_AES_IV, 
		sizeof (SESSION_AES_IV));

	setup_session_manager_ecc_test (test, &cmd);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.compute_shared_secret, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&cmd.ecc.mock, 2, SHARED_SECRET, sizeof (SHARED_SECRET), 3);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce1, sizeof (nonce1)), MOCK_ARG (sizeof (nonce1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce2, sizeof (nonce2)), MOCK_ARG (sizeof (nonce2)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET), 
		NULL, SHA256_HASH_LENGTH, aes_key, sizeof (aes_key));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x10, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.aes.mock, cmd.aes.base.set_key, &cmd.aes, 0, 
		MOCK_ARG_PTR_CONTAINS_TMP (aes_key, sizeof (aes_key)), MOCK_ARG (sizeof (aes_key)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.aes.mock, cmd.aes.base.decrypt_data, &cmd.aes, 
		AES_ENGINE_NO_MEMORY, MOCK_ARG_PTR_CONTAINS (msg, sizeof (data)), MOCK_ARG (sizeof (data)), 
		MOCK_ARG_PTR_CONTAINS (SESSION_AES_GCM_TAG, sizeof (SESSION_AES_GCM_TAG)), 
		MOCK_ARG_PTR_CONTAINS (SESSION_AES_IV, sizeof (SESSION_AES_IV)), 
		MOCK_ARG (sizeof (SESSION_AES_IV)), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.decrypt_message (&cmd.session.base, 0x10, msg, sizeof (msg), 
		sizeof (msg));
	CuAssertIntEquals (test, AES_ENGINE_NO_MEMORY, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_decrypt_message_invalid_message (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t msg[33];
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.decrypt_message (&cmd.session.base, 0x10, msg, 28, 
		sizeof (msg));
	CuAssertIntEquals (test, SESSION_MANAGER_MALFORMED_MSG, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_decrypt_message_invalid_arg (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t msg[33];
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.decrypt_message (NULL, 0x10, msg, sizeof (msg), 
		sizeof (msg));
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = cmd.session.base.decrypt_message (&cmd.session.base, 0x10, NULL, sizeof (msg), 
		sizeof (msg));
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = cmd.session.base.decrypt_message (&cmd.session.base, 0x10, msg, sizeof (msg), 
		4);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_encrypt_message (CuTest *test)
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
	uint8_t data[] = {
		0xA,0xB,0xC,0xD,0xE
	};
	uint8_t encrypted[] = {
		0x1,0x2,0x3,0x4,0x5
	};
	uint8_t aes_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;
	uint8_t encrypted_buf[33];

	TEST_START;

	memcpy (encrypted_buf, data, sizeof (data));

	setup_session_manager_ecc_test (test, &cmd);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.compute_shared_secret, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&cmd.ecc.mock, 2, SHARED_SECRET, sizeof (SHARED_SECRET), 3);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce1, sizeof (nonce1)), MOCK_ARG (sizeof (nonce1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce2, sizeof (nonce2)), MOCK_ARG (sizeof (nonce2)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET), 
		NULL, SHA256_HASH_LENGTH, aes_key, sizeof (aes_key));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x10, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.aes.mock, cmd.aes.base.set_key, &cmd.aes, 0, 
		MOCK_ARG_PTR_CONTAINS_TMP (aes_key, sizeof (aes_key)), MOCK_ARG (sizeof (aes_key)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.rng.mock, cmd.rng.base.generate_random_buffer, &cmd.rng, 0,
		MOCK_ARG (sizeof (SESSION_AES_IV)), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.rng.mock, 1, SESSION_AES_IV, sizeof (SESSION_AES_IV), 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.aes.mock, cmd.aes.base.encrypt_data, &cmd.aes, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (data, sizeof (data)), MOCK_ARG (sizeof (data)), 
		MOCK_ARG_PTR_CONTAINS (SESSION_AES_IV, sizeof (SESSION_AES_IV)), 
		MOCK_ARG (sizeof (SESSION_AES_IV)), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY, MOCK_ARG_NOT_NULL, 
		MOCK_ARG_ANY);
	status |= mock_expect_output (&cmd.aes.mock, 4, encrypted, sizeof (encrypted), 5);
	status |= mock_expect_output (&cmd.aes.mock, 6, SESSION_AES_GCM_TAG, 
		sizeof (SESSION_AES_GCM_TAG), -1);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.encrypt_message (&cmd.session.base, 0x10, encrypted_buf, 
		sizeof (data), sizeof (encrypted_buf));
	CuAssertIntEquals (test, 
		sizeof (encrypted) + CERBERUS_PROTOCOL_AES_GCM_TAG_LEN + CERBERUS_PROTOCOL_AES_IV_LEN, 
		status);

	status = testing_validate_array (encrypted, encrypted_buf, sizeof (encrypted));
	status |= testing_validate_array (SESSION_AES_GCM_TAG, &encrypted_buf[sizeof (encrypted)], 
		sizeof (SESSION_AES_GCM_TAG));
	status |= testing_validate_array (SESSION_AES_IV, 
		&encrypted_buf[sizeof (encrypted) + sizeof (SESSION_AES_GCM_TAG)], sizeof (SESSION_AES_IV));
	CuAssertIntEquals (test, 0, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_encrypt_message_unexpected_eid (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[] = {
		0xA,0xB,0xC,0xD,0xE
	};
	uint8_t encrypted_buf[33];
	int status;

	TEST_START;

	memcpy (encrypted_buf, data, sizeof (data));

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.encrypt_message (&cmd.session.base, 0x11, encrypted_buf, 
		sizeof (data), sizeof (encrypted_buf));
	CuAssertIntEquals (test, SESSION_MANAGER_UNEXPECTED_EID, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_encrypt_message_session_not_established (CuTest *test)
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
	uint8_t data[] = {
		0xA,0xB,0xC,0xD,0xE
	};
	uint8_t encrypted_buf[33];
	int status;

	TEST_START;

	memcpy (encrypted_buf, data, sizeof (data));

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.encrypt_message (&cmd.session.base, 0x10, encrypted_buf, 
		sizeof (data), sizeof (encrypted_buf));
	CuAssertIntEquals (test, SESSION_MANAGER_SESSION_NOT_ESTABLISHED, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_encrypt_message_set_key_fail (CuTest *test)
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
	uint8_t data[] = {
		0xA,0xB,0xC,0xD,0xE
	};
	uint8_t aes_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;
	uint8_t encrypted_buf[33];

	TEST_START;

	memcpy (encrypted_buf, data, sizeof (data));

	setup_session_manager_ecc_test (test, &cmd);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.compute_shared_secret, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&cmd.ecc.mock, 2, SHARED_SECRET, sizeof (SHARED_SECRET), 3);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce1, sizeof (nonce1)), MOCK_ARG (sizeof (nonce1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce2, sizeof (nonce2)), MOCK_ARG (sizeof (nonce2)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET), 
		NULL, SHA256_HASH_LENGTH, aes_key, sizeof (aes_key));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x10, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.aes.mock, cmd.aes.base.set_key, &cmd.aes, AES_ENGINE_NO_MEMORY, 
		MOCK_ARG_PTR_CONTAINS_TMP (aes_key, sizeof (aes_key)), MOCK_ARG (sizeof (aes_key)));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.encrypt_message (&cmd.session.base, 0x10, encrypted_buf, 
		sizeof (data), sizeof (encrypted_buf));
	CuAssertIntEquals (test, AES_ENGINE_NO_MEMORY, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_encrypt_message_generate_iv_fail (CuTest *test)
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
	uint8_t data[] = {
		0xA,0xB,0xC,0xD,0xE
	};
	uint8_t aes_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;
	uint8_t encrypted_buf[33];

	TEST_START;

	memcpy (encrypted_buf, data, sizeof (data));

	setup_session_manager_ecc_test (test, &cmd);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.compute_shared_secret, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&cmd.ecc.mock, 2, SHARED_SECRET, sizeof (SHARED_SECRET), 3);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce1, sizeof (nonce1)), MOCK_ARG (sizeof (nonce1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce2, sizeof (nonce2)), MOCK_ARG (sizeof (nonce2)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET), 
		NULL, SHA256_HASH_LENGTH, aes_key, sizeof (aes_key));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x10, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.aes.mock, cmd.aes.base.set_key, &cmd.aes, 0, 
		MOCK_ARG_PTR_CONTAINS_TMP (aes_key, sizeof (aes_key)), MOCK_ARG (sizeof (aes_key)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.rng.mock, cmd.rng.base.generate_random_buffer, &cmd.rng, 
		RNG_ENGINE_NO_MEMORY, MOCK_ARG (sizeof (SESSION_AES_IV)), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.rng.mock, 1, SESSION_AES_IV, sizeof (SESSION_AES_IV), 0);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.encrypt_message (&cmd.session.base, 0x10, encrypted_buf, 
		sizeof (data), sizeof (encrypted_buf));
	CuAssertIntEquals (test, RNG_ENGINE_NO_MEMORY, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_encrypt_message_fail (CuTest *test)
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
	uint8_t data[] = {
		0xA,0xB,0xC,0xD,0xE
	};
	uint8_t aes_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;
	uint8_t encrypted_buf[33];

	TEST_START;

	memcpy (encrypted_buf, data, sizeof (data));

	setup_session_manager_ecc_test (test, &cmd);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.compute_shared_secret, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&cmd.ecc.mock, 2, SHARED_SECRET, sizeof (SHARED_SECRET), 3);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce1, sizeof (nonce1)), MOCK_ARG (sizeof (nonce1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce2, sizeof (nonce2)), MOCK_ARG (sizeof (nonce2)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET), 
		NULL, SHA256_HASH_LENGTH, aes_key, sizeof (aes_key));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x10, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.aes.mock, cmd.aes.base.set_key, &cmd.aes, 0, 
		MOCK_ARG_PTR_CONTAINS_TMP (aes_key, sizeof (aes_key)), MOCK_ARG (sizeof (aes_key)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.rng.mock, cmd.rng.base.generate_random_buffer, &cmd.rng, 0,
		MOCK_ARG (sizeof (SESSION_AES_IV)), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.rng.mock, 1, SESSION_AES_IV, sizeof (SESSION_AES_IV), 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.aes.mock, cmd.aes.base.encrypt_data, &cmd.aes, 
		AES_ENGINE_NO_MEMORY, MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), 
		MOCK_ARG_PTR_CONTAINS (SESSION_AES_IV, sizeof (SESSION_AES_IV)), 
		MOCK_ARG (sizeof (SESSION_AES_IV)), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY, MOCK_ARG_NOT_NULL, 
		MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.encrypt_message (&cmd.session.base, 0x10, encrypted_buf, 
		sizeof (data), sizeof (encrypted_buf));
	CuAssertIntEquals (test, AES_ENGINE_NO_MEMORY, status);
	
	release_session_manager_ecc_test (test, &cmd);
}

static void session_manager_ecc_test_encrypt_message_invalid_arg (CuTest *test)
{
	struct session_manager_ecc_testing cmd;
	uint8_t data[] = {
		0xA,0xB,0xC,0xD,0xE
	};
	uint8_t encrypted_buf[33];
	uint8_t aes_gcm_tag[16];
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = cmd.session.base.encrypt_message (NULL, 0x10, encrypted_buf, sizeof (data), 
		sizeof (encrypted_buf));
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = cmd.session.base.encrypt_message (&cmd.session.base, 0x10, NULL, sizeof (data), 
		sizeof (encrypted_buf));
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = cmd.session.base.encrypt_message (&cmd.session.base, 0x10, encrypted_buf, 0, 
		sizeof (encrypted_buf));
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	status = cmd.session.base.encrypt_message (&cmd.session.base, 0x10, encrypted_buf, 
		sizeof (data), sizeof (data) + CERBERUS_PROTOCOL_AES_GCM_TAG_LEN + 
		CERBERUS_PROTOCOL_AES_IV_LEN - 1);
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
	uint8_t aes_key[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int status;

	TEST_START;

	setup_session_manager_ecc_test (test, &cmd);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_key_pair, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.init_public_key, &cmd.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&cmd.ecc.mock, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.get_shared_secret_max_length, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.compute_shared_secret, &cmd.ecc, 64,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&cmd.ecc.mock, 2, SHARED_SECRET, sizeof (SHARED_SECRET), 3);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce1, sizeof (nonce1)), MOCK_ARG (sizeof (nonce1)));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&nonce2, sizeof (nonce2)), MOCK_ARG (sizeof (nonce2)));
	status |= hash_mock_expect_hmac_finish (&cmd.hash, SHARED_SECRET, sizeof (SHARED_SECRET), 
		NULL, SHA256_HASH_LENGTH, aes_key, sizeof (aes_key));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.ecc.mock, cmd.ecc.base.release_key_pair, &cmd.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.add_session (&cmd.session.base, 0x10, nonce1, nonce2);
	CuAssertIntEquals (test, 0, status);

	status = cmd.session.base.establish_session (&cmd.session.base, 0x10, ECC_PUBKEY_DER, 
		ECC_PUBKEY_DER_LEN, true);
	CuAssertIntEquals (test, 0, status);

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
	CuAssertIntEquals (test, SESSION_MANAGER_UNEXPECTED_EID, status);
	
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

CuSuite* get_session_manager_ecc_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, session_manager_ecc_test_init);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_init_invalid_arg);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_init_preallocated_table);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_init_preallocated_table_invalid_arg);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_release_null);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_add_session);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_add_session_restart);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_add_session_full);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_add_session_invalid_arg);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_establish_session);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_establish_session_paired);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_establish_session_replace);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_establish_session_paired_unexpected_key);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_establish_session_invalid_order);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_establish_session_unexpected_eid);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_establish_session_init_priv_key_fail);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_establish_session_init_pub_key_fail);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_establish_session_size_shared_secret_fail);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_establish_session_compute_shared_secret_fail);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_establish_session_init_hmac_fail);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_establish_session_update1_hmac_fail);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_establish_session_update2_hmac_fail);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_establish_session_finish_hmac_fail);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_establish_session_invalid_arg);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_decrypt_message);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_decrypt_message_unexpected_eid);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_decrypt_message_session_not_established);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_decrypt_message_set_key_fail);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_decrypt_message_fail);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_decrypt_message_invalid_message);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_decrypt_message_invalid_arg);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_encrypt_message);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_encrypt_message_unexpected_eid);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_encrypt_message_session_not_established);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_encrypt_message_set_key_fail);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_encrypt_message_generate_iv_fail);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_encrypt_message_fail);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_encrypt_message_invalid_arg);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_is_session_established);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_is_session_established_unexpected_eid);
	SUITE_ADD_TEST (suite, session_manager_ecc_test_is_session_established_invalid_arg);

	return suite;
}
