// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "common/shared_buffer.h"
#include "common/shared_buffer_interface.h"
#include "common/shared_buffer_static.h"


TEST_SUITE_LABEL ("shared_buffer");


/**
 * Size of the buffer region used for testing.
 */
#define	SHARED_BUFFER_TESTING_SIZE	256


/*******************
 * Test cases
 *******************/

static void shared_buffer_test_init (CuTest *test)
{
	struct shared_buffer_state state;
	struct shared_buffer shared;
	uint8_t region[SHARED_BUFFER_TESTING_SIZE];
	int status;

	TEST_START;

	status = shared_buffer_init (&shared, &state, region, sizeof (region));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, shared.base.get_buffer_size);
	CuAssertPtrNotNull (test, shared.base.lock);
	CuAssertPtrNotNull (test, shared.base.unlock);

	shared_buffer_release (&shared);
}

static void shared_buffer_test_init_state_null (CuTest *test)
{
	struct shared_buffer_state state;
	uint8_t region[SHARED_BUFFER_TESTING_SIZE];
	struct shared_buffer null_state =
		shared_buffer_static_init (NULL, region, sizeof (region));
	struct shared_buffer null_buffer =
		shared_buffer_static_init (&state, NULL, sizeof (region));
	struct shared_buffer zero_size =
		shared_buffer_static_init (&state, region, 0);
	int status;

	TEST_START;

	status = shared_buffer_init_state (NULL);
	CuAssertIntEquals (test, SHARED_BUFFER_INVALID_ARGUMENT, status);

	status = shared_buffer_init_state (&null_state);
	CuAssertIntEquals (test, SHARED_BUFFER_INVALID_ARGUMENT, status);

	status = shared_buffer_init_state (&null_buffer);
	CuAssertIntEquals (test, SHARED_BUFFER_INVALID_ARGUMENT, status);

	status = shared_buffer_init_state (&zero_size);
	CuAssertIntEquals (test, SHARED_BUFFER_INVALID_ARGUMENT, status);
}

static void shared_buffer_test_static_init (CuTest *test)
{
	struct shared_buffer_state state;
	uint8_t region[SHARED_BUFFER_TESTING_SIZE];
	struct shared_buffer shared = shared_buffer_static_init (&state, region, sizeof (region));
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, shared.base.get_buffer_size);
	CuAssertPtrNotNull (test, shared.base.lock);
	CuAssertPtrNotNull (test, shared.base.unlock);

	status = shared_buffer_init_state (&shared);
	CuAssertIntEquals (test, 0, status);

	shared_buffer_release (&shared);
}

static void shared_buffer_test_init_null (CuTest *test)
{
	struct shared_buffer_state state;
	struct shared_buffer shared;
	uint8_t region[SHARED_BUFFER_TESTING_SIZE];
	int status;

	TEST_START;

	status = shared_buffer_init (NULL, &state, region, sizeof (region));
	CuAssertIntEquals (test, SHARED_BUFFER_INVALID_ARGUMENT, status);

	status = shared_buffer_init (&shared, NULL, region, sizeof (region));
	CuAssertIntEquals (test, SHARED_BUFFER_INVALID_ARGUMENT, status);

	status = shared_buffer_init (&shared, &state, NULL, sizeof (region));
	CuAssertIntEquals (test, SHARED_BUFFER_INVALID_ARGUMENT, status);

	status = shared_buffer_init (&shared, &state, region, 0);
	CuAssertIntEquals (test, SHARED_BUFFER_INVALID_ARGUMENT, status);
}

static void shared_buffer_test_release_null (CuTest *test)
{
	TEST_START;

	shared_buffer_release (NULL);
}

static void shared_buffer_test_get_buffer_size (CuTest *test)
{
	struct shared_buffer_state state;
	struct shared_buffer shared;
	uint8_t region[SHARED_BUFFER_TESTING_SIZE];
	size_t size;
	int status;

	TEST_START;

	status = shared_buffer_init (&shared, &state, region, sizeof (region));
	CuAssertIntEquals (test, 0, status);

	status = shared.base.get_buffer_size (&shared.base, &size);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (region), size);

	shared_buffer_release (&shared);
}

static void shared_buffer_test_get_buffer_size_static_init (CuTest *test)
{
	struct shared_buffer_state state;
	uint8_t region[SHARED_BUFFER_TESTING_SIZE];
	struct shared_buffer shared = shared_buffer_static_init (&state, region, sizeof (region));
	size_t size;
	int status;

	TEST_START;

	status = shared_buffer_init_state (&shared);
	CuAssertIntEquals (test, 0, status);

	status = shared.base.get_buffer_size (&shared.base, &size);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (region), size);

	shared_buffer_release (&shared);
}

static void shared_buffer_test_get_buffer_size_null (CuTest *test)
{
	struct shared_buffer_state state;
	struct shared_buffer shared;
	uint8_t region[SHARED_BUFFER_TESTING_SIZE];
	size_t size;
	int status;

	TEST_START;

	status = shared_buffer_init (&shared, &state, region, sizeof (region));
	CuAssertIntEquals (test, 0, status);

	status = shared.base.get_buffer_size (NULL, &size);
	CuAssertIntEquals (test, SHARED_BUFFER_INVALID_ARGUMENT, status);

	status = shared.base.get_buffer_size (&shared.base, NULL);
	CuAssertIntEquals (test, SHARED_BUFFER_INVALID_ARGUMENT, status);

	shared_buffer_release (&shared);
}

static void shared_buffer_test_get_buffer_size_while_held (CuTest *test)
{
	struct shared_buffer_state state;
	struct shared_buffer shared;
	uint8_t region[SHARED_BUFFER_TESTING_SIZE];
	struct shared_buffer_handle handle;
	size_t size;
	int status;

	TEST_START;

	status = shared_buffer_init (&shared, &state, region, sizeof (region));
	CuAssertIntEquals (test, 0, status);

	status = shared.base.lock (&shared.base, &handle);
	CuAssertIntEquals (test, 0, status);

	/* get_buffer_size is lock-free and must not perturb the held state. */
	status = shared.base.get_buffer_size (&shared.base, &size);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (region), size);

	status = shared.base.unlock (&shared.base, &handle);
	CuAssertIntEquals (test, 0, status);

	shared_buffer_release (&shared);
}

static void shared_buffer_test_lock (CuTest *test)
{
	struct shared_buffer_state state;
	struct shared_buffer shared;
	uint8_t region[SHARED_BUFFER_TESTING_SIZE];
	struct shared_buffer_handle handle;
	int status;

	TEST_START;

	status = shared_buffer_init (&shared, &state, region, sizeof (region));
	CuAssertIntEquals (test, 0, status);

	status = shared.base.lock (&shared.base, &handle);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, region, handle.ptr);
	CuAssertIntEquals (test, sizeof (region), handle.size);

	/* The region is accessible through the handle for the whole lock span. */
	memset (handle.ptr, 0xa5, handle.size);
	CuAssertIntEquals (test, 0xa5, region[0]);
	CuAssertIntEquals (test, 0xa5, region[sizeof (region) - 1]);

	status = shared.base.unlock (&shared.base, &handle);
	CuAssertIntEquals (test, 0, status);

	shared_buffer_release (&shared);
}

static void shared_buffer_test_lock_static_init (CuTest *test)
{
	struct shared_buffer_state state;
	uint8_t region[SHARED_BUFFER_TESTING_SIZE];
	struct shared_buffer shared = shared_buffer_static_init (&state, region, sizeof (region));
	struct shared_buffer_handle handle;
	int status;

	TEST_START;

	status = shared_buffer_init_state (&shared);
	CuAssertIntEquals (test, 0, status);

	status = shared.base.lock (&shared.base, &handle);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, region, handle.ptr);
	CuAssertIntEquals (test, sizeof (region), handle.size);

	status = shared.base.unlock (&shared.base, &handle);
	CuAssertIntEquals (test, 0, status);

	shared_buffer_release (&shared);
}

static void shared_buffer_test_lock_null (CuTest *test)
{
	struct shared_buffer_state state;
	struct shared_buffer shared;
	uint8_t region[SHARED_BUFFER_TESTING_SIZE];
	struct shared_buffer_handle handle;
	int status;

	TEST_START;

	status = shared_buffer_init (&shared, &state, region, sizeof (region));
	CuAssertIntEquals (test, 0, status);

	status = shared.base.lock (NULL, &handle);
	CuAssertIntEquals (test, SHARED_BUFFER_INVALID_ARGUMENT, status);

	status = shared.base.lock (&shared.base, NULL);
	CuAssertIntEquals (test, SHARED_BUFFER_INVALID_ARGUMENT, status);

	shared_buffer_release (&shared);
}

static void shared_buffer_test_lock_already_held (CuTest *test)
{
	struct shared_buffer_state state;
	struct shared_buffer shared;
	uint8_t region[SHARED_BUFFER_TESTING_SIZE];
	struct shared_buffer_handle handle;
	struct shared_buffer_handle second;
	int status;

	TEST_START;

	status = shared_buffer_init (&shared, &state, region, sizeof (region));
	CuAssertIntEquals (test, 0, status);

	status = shared.base.lock (&shared.base, &handle);
	CuAssertIntEquals (test, 0, status);

	status = shared.base.lock (&shared.base, &second);
	CuAssertIntEquals (test, SHARED_BUFFER_BUSY, status);

	status = shared.base.unlock (&shared.base, &handle);
	CuAssertIntEquals (test, 0, status);

	shared_buffer_release (&shared);
}

static void shared_buffer_test_unlock_not_held (CuTest *test)
{
	struct shared_buffer_state state;
	struct shared_buffer shared;
	uint8_t region[SHARED_BUFFER_TESTING_SIZE];
	struct shared_buffer_handle handle;
	int status;

	TEST_START;

	status = shared_buffer_init (&shared, &state, region, sizeof (region));
	CuAssertIntEquals (test, 0, status);

	memset (&handle, 0, sizeof (handle));

	status = shared.base.unlock (&shared.base, &handle);
	CuAssertIntEquals (test, SHARED_BUFFER_NOT_HELD, status);

	shared_buffer_release (&shared);
}

static void shared_buffer_test_unlock_after_unlock (CuTest *test)
{
	struct shared_buffer_state state;
	struct shared_buffer shared;
	uint8_t region[SHARED_BUFFER_TESTING_SIZE];
	struct shared_buffer_handle handle;
	int status;

	TEST_START;

	status = shared_buffer_init (&shared, &state, region, sizeof (region));
	CuAssertIntEquals (test, 0, status);

	status = shared.base.lock (&shared.base, &handle);
	CuAssertIntEquals (test, 0, status);

	status = shared.base.unlock (&shared.base, &handle);
	CuAssertIntEquals (test, 0, status);

	status = shared.base.unlock (&shared.base, &handle);
	CuAssertIntEquals (test, SHARED_BUFFER_NOT_HELD, status);

	shared_buffer_release (&shared);
}

static void shared_buffer_test_unlock_wrong_owner (CuTest *test)
{
	struct shared_buffer_state state;
	struct shared_buffer shared;
	uint8_t region[SHARED_BUFFER_TESTING_SIZE];
	struct shared_buffer_handle handle;
	struct shared_buffer_handle forged;
	int status;

	TEST_START;

	status = shared_buffer_init (&shared, &state, region, sizeof (region));
	CuAssertIntEquals (test, 0, status);

	status = shared.base.lock (&shared.base, &handle);
	CuAssertIntEquals (test, 0, status);

	forged = handle;
	forged.owner = handle.owner + 1;

	status = shared.base.unlock (&shared.base, &forged);
	CuAssertIntEquals (test, SHARED_BUFFER_WRONG_OWNER, status);

	/* The genuine handle still releases the buffer. */
	status = shared.base.unlock (&shared.base, &handle);
	CuAssertIntEquals (test, 0, status);

	shared_buffer_release (&shared);
}

static void shared_buffer_test_unlock_stale_handle (CuTest *test)
{
	struct shared_buffer_state state;
	struct shared_buffer shared;
	uint8_t region[SHARED_BUFFER_TESTING_SIZE];
	struct shared_buffer_handle stale;
	struct shared_buffer_handle current;
	int status;

	TEST_START;

	status = shared_buffer_init (&shared, &state, region, sizeof (region));
	CuAssertIntEquals (test, 0, status);

	/* Capture a handle from a completed lock/unlock cycle. */
	status = shared.base.lock (&shared.base, &stale);
	CuAssertIntEquals (test, 0, status);

	status = shared.base.unlock (&shared.base, &stale);
	CuAssertIntEquals (test, 0, status);

	/* A new holder owns the buffer; the stale handle must not release it. */
	status = shared.base.lock (&shared.base, &current);
	CuAssertIntEquals (test, 0, status);

	status = shared.base.unlock (&shared.base, &stale);
	CuAssertIntEquals (test, SHARED_BUFFER_WRONG_OWNER, status);

	status = shared.base.unlock (&shared.base, &current);
	CuAssertIntEquals (test, 0, status);

	shared_buffer_release (&shared);
}

static void shared_buffer_test_unlock_static_init (CuTest *test)
{
	struct shared_buffer_state state;
	uint8_t region[SHARED_BUFFER_TESTING_SIZE];
	struct shared_buffer shared = shared_buffer_static_init (&state, region, sizeof (region));
	struct shared_buffer_handle handle;
	int status;

	TEST_START;

	status = shared_buffer_init_state (&shared);
	CuAssertIntEquals (test, 0, status);

	status = shared.base.lock (&shared.base, &handle);
	CuAssertIntEquals (test, 0, status);

	status = shared.base.unlock (&shared.base, &handle);
	CuAssertIntEquals (test, 0, status);

	shared_buffer_release (&shared);
}

static void shared_buffer_test_unlock_null (CuTest *test)
{
	struct shared_buffer_state state;
	struct shared_buffer shared;
	uint8_t region[SHARED_BUFFER_TESTING_SIZE];
	struct shared_buffer_handle handle;
	int status;

	TEST_START;

	status = shared_buffer_init (&shared, &state, region, sizeof (region));
	CuAssertIntEquals (test, 0, status);

	status = shared.base.lock (&shared.base, &handle);
	CuAssertIntEquals (test, 0, status);

	status = shared.base.unlock (NULL, &handle);
	CuAssertIntEquals (test, SHARED_BUFFER_INVALID_ARGUMENT, status);

	status = shared.base.unlock (&shared.base, NULL);
	CuAssertIntEquals (test, SHARED_BUFFER_INVALID_ARGUMENT, status);

	status = shared.base.unlock (&shared.base, &handle);
	CuAssertIntEquals (test, 0, status);

	shared_buffer_release (&shared);
}

static void shared_buffer_test_unlock_clears_handle (CuTest *test)
{
	struct shared_buffer_state state;
	struct shared_buffer shared;
	uint8_t region[SHARED_BUFFER_TESTING_SIZE];
	struct shared_buffer_handle handle;
	struct shared_buffer_handle next;
	int status;

	TEST_START;

	status = shared_buffer_init (&shared, &state, region, sizeof (region));
	CuAssertIntEquals (test, 0, status);

	status = shared.base.lock (&shared.base, &handle);
	CuAssertIntEquals (test, 0, status);

	status = shared.base.unlock (&shared.base, &handle);
	CuAssertIntEquals (test, 0, status);

	/* The handle is scrubbed so a stale region pointer can't be reused. */
	CuAssertPtrEquals (test, NULL, handle.ptr);
	CuAssertIntEquals (test, 0, handle.size);
	CuAssertIntEquals (test, 0, handle.owner);

	/* A new holder takes the buffer; the cleared handle must not release it. */
	status = shared.base.lock (&shared.base, &next);
	CuAssertIntEquals (test, 0, status);

	status = shared.base.unlock (&shared.base, &handle);
	CuAssertIntEquals (test, SHARED_BUFFER_WRONG_OWNER, status);

	status = shared.base.unlock (&shared.base, &next);
	CuAssertIntEquals (test, 0, status);

	shared_buffer_release (&shared);
}

static void shared_buffer_test_lock_unlock_round_trip (CuTest *test)
{
	struct shared_buffer_state state;
	struct shared_buffer shared;
	uint8_t region[SHARED_BUFFER_TESTING_SIZE];
	struct shared_buffer_handle handle;
	int status;
	int i;

	TEST_START;

	status = shared_buffer_init (&shared, &state, region, sizeof (region));
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 5; i++) {
		status = shared.base.lock (&shared.base, &handle);
		CuAssertIntEquals (test, 0, status);
		CuAssertPtrEquals (test, region, handle.ptr);

		status = shared.base.unlock (&shared.base, &handle);
		CuAssertIntEquals (test, 0, status);
	}

	shared_buffer_release (&shared);
}


// *INDENT-OFF*
TEST_SUITE_START (shared_buffer);

TEST (shared_buffer_test_init);
TEST (shared_buffer_test_init_state_null);
TEST (shared_buffer_test_static_init);
TEST (shared_buffer_test_init_null);
TEST (shared_buffer_test_release_null);
TEST (shared_buffer_test_get_buffer_size);
TEST (shared_buffer_test_get_buffer_size_static_init);
TEST (shared_buffer_test_get_buffer_size_null);
TEST (shared_buffer_test_get_buffer_size_while_held);
TEST (shared_buffer_test_lock);
TEST (shared_buffer_test_lock_static_init);
TEST (shared_buffer_test_lock_null);
TEST (shared_buffer_test_lock_already_held);
TEST (shared_buffer_test_unlock_not_held);
TEST (shared_buffer_test_unlock_after_unlock);
TEST (shared_buffer_test_unlock_wrong_owner);
TEST (shared_buffer_test_unlock_stale_handle);
TEST (shared_buffer_test_unlock_static_init);
TEST (shared_buffer_test_unlock_null);
TEST (shared_buffer_test_unlock_clears_handle);
TEST (shared_buffer_test_lock_unlock_round_trip);

TEST_SUITE_END;
// *INDENT-ON*
