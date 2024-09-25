// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "cmd_interface/session_manager_null.h"
#include "cmd_interface/session_manager_null_static.h"


TEST_SUITE_LABEL ("session_manager_null");

/*******************
 * Test cases
 *******************/

static void session_manager_null_test_init (CuTest *test)
{
	struct session_manager_null session;
	int status;

	TEST_START;

	status = session_manager_null_init (&session);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, session.base.add_session);
	CuAssertPtrNotNull (test, session.base.establish_session);
	CuAssertPtrNotNull (test, session.base.is_session_established);
	CuAssertPtrNotNull (test, session.base.get_pairing_state);
	CuAssertPtrNotNull (test, session.base.decrypt_message);
	CuAssertPtrNotNull (test, session.base.encrypt_message);
	CuAssertPtrNotNull (test, session.base.reset_session);
	CuAssertPtrNotNull (test, session.base.setup_paired_session);
	CuAssertPtrNotNull (test, session.base.session_sync);

	session_manager_null_release (&session);
}

static void session_manager_null_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = session_manager_null_init (NULL);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	session_manager_null_release (NULL);
}

static void session_manager_null_test_static_init (CuTest *test)
{
	struct session_manager_null session = session_manager_null_static_init;

	TEST_START;

	CuAssertPtrNotNull (test, session.base.add_session);
	CuAssertPtrNotNull (test, session.base.establish_session);
	CuAssertPtrNotNull (test, session.base.is_session_established);
	CuAssertPtrNotNull (test, session.base.get_pairing_state);
	CuAssertPtrNotNull (test, session.base.decrypt_message);
	CuAssertPtrNotNull (test, session.base.encrypt_message);
	CuAssertPtrNotNull (test, session.base.reset_session);
	CuAssertPtrNotNull (test, session.base.setup_paired_session);
	CuAssertPtrNotNull (test, session.base.session_sync);

	session_manager_null_release (&session);
}

static void session_manager_null_test_release_null (CuTest *test)
{
	TEST_START;

	session_manager_null_release (NULL);
}

static void session_manager_null_test_add_session (CuTest *test)
{
	struct session_manager_null session;
	int status;

	TEST_START;

	status = session_manager_null_init (&session);
	CuAssertIntEquals (test, 0, status);

	status = session.base.add_session (&session.base, 0x10, NULL, NULL);
	CuAssertIntEquals (test, SESSION_MANAGER_OPERATION_UNSUPPORTED, status);

	session_manager_null_release (&session);
}

static void session_manager_null_test_add_session_static_init (CuTest *test)
{
	struct session_manager_null session = session_manager_null_static_init;
	int status;

	TEST_START;

	status = session.base.add_session (&session.base, 0x10, NULL, NULL);
	CuAssertIntEquals (test, SESSION_MANAGER_OPERATION_UNSUPPORTED, status);

	session_manager_null_release (&session);
}

static void session_manager_null_test_add_session_null (CuTest *test)
{
	struct session_manager_null session;
	int status;

	TEST_START;

	status = session_manager_null_init (&session);
	CuAssertIntEquals (test, 0, status);

	status = session.base.add_session (NULL, 0x10, NULL, NULL);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	session_manager_null_release (&session);
}

static void session_manager_null_test_establish_session (CuTest *test)
{
	struct session_manager_null session;
	int status;

	TEST_START;

	status = session_manager_null_init (&session);
	CuAssertIntEquals (test, 0, status);

	status = session.base.establish_session (&session.base, NULL);
	CuAssertIntEquals (test, SESSION_MANAGER_OPERATION_UNSUPPORTED, status);

	session_manager_null_release (&session);
}

static void session_manager_null_test_establish_session_static_init (CuTest *test)
{
	struct session_manager_null session = session_manager_null_static_init;
	int status;

	TEST_START;

	status = session.base.establish_session (&session.base, NULL);
	CuAssertIntEquals (test, SESSION_MANAGER_OPERATION_UNSUPPORTED, status);

	session_manager_null_release (&session);
}

static void session_manager_null_test_establish_session_null (CuTest *test)
{
	struct session_manager_null session;
	int status;

	TEST_START;

	status = session_manager_null_init (&session);
	CuAssertIntEquals (test, 0, status);

	status = session.base.establish_session (NULL, NULL);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	session_manager_null_release (&session);
}

static void session_manager_null_test_is_session_established (CuTest *test)
{
	struct session_manager_null session;
	int status;

	TEST_START;

	status = session_manager_null_init (&session);
	CuAssertIntEquals (test, 0, status);

	status = session.base.is_session_established (&session.base, 0x10);
	CuAssertIntEquals (test, false, status);

	session_manager_null_release (&session);
}

static void session_manager_null_test_is_session_established_static_init (CuTest *test)
{
	struct session_manager_null session = session_manager_null_static_init;
	int status;

	TEST_START;

	status = session.base.is_session_established (&session.base, 0x10);
	CuAssertIntEquals (test, false, status);

	session_manager_null_release (&session);
}

static void session_manager_null_test_is_session_established_null (CuTest *test)
{
	struct session_manager_null session;
	int status;

	TEST_START;

	status = session_manager_null_init (&session);
	CuAssertIntEquals (test, 0, status);

	status = session.base.is_session_established (NULL, 0x10);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	session_manager_null_release (&session);
}

static void session_manager_null_test_get_pairing_state (CuTest *test)
{
	struct session_manager_null session;
	int status;

	TEST_START;

	status = session_manager_null_init (&session);
	CuAssertIntEquals (test, 0, status);

	status = session.base.get_pairing_state (&session.base, 0x10);
	CuAssertIntEquals (test, SESSION_PAIRING_STATE_NOT_SUPPORTED, status);

	session_manager_null_release (&session);
}

static void session_manager_null_test_get_pairing_state_static_init (CuTest *test)
{
	struct session_manager_null session = session_manager_null_static_init;
	int status;

	TEST_START;

	status = session.base.get_pairing_state (&session.base, 0x10);
	CuAssertIntEquals (test, SESSION_PAIRING_STATE_NOT_SUPPORTED, status);

	session_manager_null_release (&session);
}

static void session_manager_null_test_get_pairing_state_null (CuTest *test)
{
	struct session_manager_null session;
	int status;

	TEST_START;

	status = session_manager_null_init (&session);
	CuAssertIntEquals (test, 0, status);

	status = session.base.get_pairing_state (NULL, 0x10);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	session_manager_null_release (&session);
}

static void session_manager_null_test_decrypt_message (CuTest *test)
{
	struct session_manager_null session;
	int status;

	TEST_START;

	status = session_manager_null_init (&session);
	CuAssertIntEquals (test, 0, status);

	status = session.base.decrypt_message (&session.base, NULL);
	CuAssertIntEquals (test, SESSION_MANAGER_OPERATION_UNSUPPORTED, status);

	session_manager_null_release (&session);
}

static void session_manager_null_test_decrypt_message_static_init (CuTest *test)
{
	struct session_manager_null session = session_manager_null_static_init;
	int status;

	TEST_START;

	status = session.base.decrypt_message (&session.base, NULL);
	CuAssertIntEquals (test, SESSION_MANAGER_OPERATION_UNSUPPORTED, status);

	session_manager_null_release (&session);
}

static void session_manager_null_test_decrypt_message_null (CuTest *test)
{
	struct session_manager_null session;
	int status;

	TEST_START;

	status = session_manager_null_init (&session);
	CuAssertIntEquals (test, 0, status);

	status = session.base.decrypt_message (NULL, NULL);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	session_manager_null_release (&session);
}

static void session_manager_null_test_encrypt_message (CuTest *test)
{
	struct session_manager_null session;
	int status;

	TEST_START;

	status = session_manager_null_init (&session);
	CuAssertIntEquals (test, 0, status);

	status = session.base.encrypt_message (&session.base, NULL);
	CuAssertIntEquals (test, 0, status);

	session_manager_null_release (&session);
}

static void session_manager_null_test_encrypt_message_static_init (CuTest *test)
{
	struct session_manager_null session = session_manager_null_static_init;
	int status;

	TEST_START;

	status = session.base.encrypt_message (&session.base, NULL);
	CuAssertIntEquals (test, 0, status);

	session_manager_null_release (&session);
}

static void session_manager_null_test_encrypt_message_null (CuTest *test)
{
	struct session_manager_null session;
	int status;

	TEST_START;

	status = session_manager_null_init (&session);
	CuAssertIntEquals (test, 0, status);

	status = session.base.encrypt_message (NULL, NULL);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	session_manager_null_release (&session);
}

static void session_manager_null_test_reset_session (CuTest *test)
{
	struct session_manager_null session;
	int status;

	TEST_START;

	status = session_manager_null_init (&session);
	CuAssertIntEquals (test, 0, status);

	status = session.base.reset_session (&session.base, 0x10, NULL, 0);
	CuAssertIntEquals (test, SESSION_MANAGER_OPERATION_UNSUPPORTED, status);

	session_manager_null_release (&session);
}

static void session_manager_null_test_reset_session_static_init (CuTest *test)
{
	struct session_manager_null session = session_manager_null_static_init;
	int status;

	TEST_START;

	status = session.base.reset_session (&session.base, 0x10, NULL, 0);
	CuAssertIntEquals (test, SESSION_MANAGER_OPERATION_UNSUPPORTED, status);

	session_manager_null_release (&session);
}

static void session_manager_null_test_reset_session_null (CuTest *test)
{
	struct session_manager_null session;
	int status;

	TEST_START;

	status = session_manager_null_init (&session);
	CuAssertIntEquals (test, 0, status);

	status = session.base.reset_session (NULL, 0x10, NULL, 0);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	session_manager_null_release (&session);
}

static void session_manager_null_test_setup_paired_session (CuTest *test)
{
	struct session_manager_null session;
	int status;

	TEST_START;

	status = session_manager_null_init (&session);
	CuAssertIntEquals (test, 0, status);

	status = session.base.setup_paired_session (&session.base, 0x10, 32, NULL, 0);
	CuAssertIntEquals (test, SESSION_MANAGER_OPERATION_UNSUPPORTED, status);

	session_manager_null_release (&session);
}

static void session_manager_null_test_setup_paired_session_static_init (CuTest *test)
{
	struct session_manager_null session = session_manager_null_static_init;
	int status;

	TEST_START;

	status = session.base.setup_paired_session (&session.base, 0x10, 32, NULL, 0);
	CuAssertIntEquals (test, SESSION_MANAGER_OPERATION_UNSUPPORTED, status);

	session_manager_null_release (&session);
}

static void session_manager_null_test_setup_paired_session_null (CuTest *test)
{
	struct session_manager_null session;
	int status;

	TEST_START;

	status = session_manager_null_init (&session);
	CuAssertIntEquals (test, 0, status);

	status = session.base.setup_paired_session (NULL, 0x10, 32, NULL, 0);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	session_manager_null_release (&session);
}

static void session_manager_null_test_session_sync (CuTest *test)
{
	struct session_manager_null session;
	int status;

	TEST_START;

	status = session_manager_null_init (&session);
	CuAssertIntEquals (test, 0, status);

	status = session.base.session_sync (&session.base, 0x10, 0, NULL, 0);
	CuAssertIntEquals (test, SESSION_MANAGER_OPERATION_UNSUPPORTED, status);

	session_manager_null_release (&session);
}

static void session_manager_null_test_session_sync_static_init (CuTest *test)
{
	struct session_manager_null session = session_manager_null_static_init;
	int status;

	TEST_START;

	status = session.base.session_sync (&session.base, 0x10, 0, NULL, 0);
	CuAssertIntEquals (test, SESSION_MANAGER_OPERATION_UNSUPPORTED, status);

	session_manager_null_release (&session);
}

static void session_manager_null_test_session_sync_null (CuTest *test)
{
	struct session_manager_null session;
	int status;

	TEST_START;

	status = session_manager_null_init (&session);
	CuAssertIntEquals (test, 0, status);

	status = session.base.session_sync (NULL, 0x10, 0, NULL, 0);
	CuAssertIntEquals (test, SESSION_MANAGER_INVALID_ARGUMENT, status);

	session_manager_null_release (&session);
}


// *INDENT-OFF*
TEST_SUITE_START (session_manager_null);

TEST (session_manager_null_test_init);
TEST (session_manager_null_test_init_null);
TEST (session_manager_null_test_static_init);
TEST (session_manager_null_test_release_null);
TEST (session_manager_null_test_add_session);
TEST (session_manager_null_test_add_session_static_init);
TEST (session_manager_null_test_add_session_null);
TEST (session_manager_null_test_establish_session);
TEST (session_manager_null_test_establish_session_static_init);
TEST (session_manager_null_test_establish_session_null);
TEST (session_manager_null_test_is_session_established);
TEST (session_manager_null_test_is_session_established_static_init);
TEST (session_manager_null_test_is_session_established_null);
TEST (session_manager_null_test_get_pairing_state);
TEST (session_manager_null_test_get_pairing_state_static_init);
TEST (session_manager_null_test_get_pairing_state_null);
TEST (session_manager_null_test_decrypt_message);
TEST (session_manager_null_test_decrypt_message_static_init);
TEST (session_manager_null_test_decrypt_message_null);
TEST (session_manager_null_test_encrypt_message);
TEST (session_manager_null_test_encrypt_message_static_init);
TEST (session_manager_null_test_encrypt_message_null);
TEST (session_manager_null_test_reset_session);
TEST (session_manager_null_test_reset_session_static_init);
TEST (session_manager_null_test_reset_session_null);
TEST (session_manager_null_test_setup_paired_session);
TEST (session_manager_null_test_setup_paired_session_static_init);
TEST (session_manager_null_test_setup_paired_session_null);
TEST (session_manager_null_test_session_sync);
TEST (session_manager_null_test_session_sync_static_init);
TEST (session_manager_null_test_session_sync_null);

TEST_SUITE_END;
// *INDENT-ON*
