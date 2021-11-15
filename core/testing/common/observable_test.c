// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "common/observable.h"
#include "testing/mock/common/observer_mock.h"


TEST_SUITE_LABEL ("observable");


/*******************
 * Test cases
 *******************/

static void observable_test_init (CuTest *test)
{
	struct observable observable;
	int status;

	TEST_START;

	status = observable_init (&observable);
	CuAssertIntEquals (test, 0, status);

	observable_release (&observable);
}

static void observable_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = observable_init (NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);
}

static void observable_test_release_null (CuTest *test)
{
	TEST_START;

	observable_release (NULL);
}

static void observable_test_notify_observers_no_observers (CuTest *test)
{
	struct observable observable;
	int status;

	TEST_START;

	status = observable_init (&observable);
	CuAssertIntEquals (test, 0, status);

	status = observable_notify_observers (&observable, offsetof (struct observer_mock, event));
	CuAssertIntEquals (test, 0, status);

	observable_release (&observable);
}

static void observable_test_notify_observers_one_observer (CuTest *test)
{
	struct observer_mock observer;
	struct observable observable;
	int status;

	TEST_START;

	status = observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = observable_init (&observable);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (&observable, &observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.event, &observer, 0);

	CuAssertIntEquals (test, 0, status);

	status = observable_notify_observers (&observable, offsetof (struct observer_mock, event));
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	observable_release (&observable);
}

static void observable_test_notify_observers_twice (CuTest *test)
{
	struct observer_mock observer;
	struct observable observable;
	int status;

	TEST_START;

	status = observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = observable_init (&observable);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (&observable, &observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.event, &observer, 0);

	CuAssertIntEquals (test, 0, status);

	status = observable_notify_observers (&observable, offsetof (struct observer_mock, event));
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&observer.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.event, &observer, 0);

	CuAssertIntEquals (test, 0, status);

	status = observable_notify_observers (&observable, offsetof (struct observer_mock, event));
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	observable_release (&observable);
}

static void observable_test_notify_observers_multiple_observers (CuTest *test)
{
	struct observer_mock observer1;
	struct observer_mock observer2;
	struct observer_mock observer3;
	struct observable observable;
	int status;

	TEST_START;

	status = observer_mock_init (&observer1);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_init (&observer2);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_init (&observer3);
	CuAssertIntEquals (test, 0, status);

	status = observable_init (&observable);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (&observable, &observer1);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (&observable, &observer2);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (&observable, &observer3);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer1.mock, observer1.event, &observer1, 0);
	status |= mock_expect (&observer2.mock, observer2.event, &observer2, 0);
	status |= mock_expect (&observer3.mock, observer3.event, &observer3, 0);

	CuAssertIntEquals (test, 0, status);

	status = observable_notify_observers (&observable, offsetof (struct observer_mock, event));
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_validate_and_release (&observer1);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_validate_and_release (&observer2);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_validate_and_release (&observer3);
	CuAssertIntEquals (test, 0, status);

	observable_release (&observable);
}

static void observable_test_notify_observers_no_event_handler (CuTest *test)
{
	struct observer_mock observer;
	struct observable observable;
	int status;

	TEST_START;

	status = observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	observer.event = NULL;

	status = observable_init (&observable);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (&observable, &observer);
	CuAssertIntEquals (test, 0, status);

	status = observable_notify_observers (&observable, offsetof (struct observer_mock, event));
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	observable_release (&observable);
}

static void observable_test_notify_observers_null (CuTest *test)
{
	struct observer_mock observer;
	struct observable observable;
	int status;

	TEST_START;

	status = observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = observable_init (&observable);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (&observable, &observer);
	CuAssertIntEquals (test, 0, status);

	status = observable_notify_observers (NULL, offsetof (struct observer_mock, event));
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	status = observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	observable_release (&observable);
}


static void observable_test_notify_observers_with_ptr_no_observers (CuTest *test)
{
	struct observable observable;
	int status;
	void *arg = &status;

	TEST_START;

	status = observable_init (&observable);
	CuAssertIntEquals (test, 0, status);

	status = observable_notify_observers_with_ptr (&observable,
		offsetof (struct observer_mock, event_ptr_arg), arg);
	CuAssertIntEquals (test, 0, status);

	observable_release (&observable);
}

static void observable_test_notify_observers_with_ptr_one_observer (CuTest *test)
{
	struct observer_mock observer;
	struct observable observable;
	int status;
	void *arg = &status;

	TEST_START;

	status = observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = observable_init (&observable);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (&observable, &observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.event_ptr_arg, &observer, 0, MOCK_ARG (arg));

	CuAssertIntEquals (test, 0, status);

	status = observable_notify_observers_with_ptr (&observable,
		offsetof (struct observer_mock, event_ptr_arg), arg);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	observable_release (&observable);
}

static void observable_test_notify_observers_with_ptr_twice (CuTest *test)
{
	struct observer_mock observer;
	struct observable observable;
	int status;
	void *arg = &status;

	TEST_START;

	status = observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = observable_init (&observable);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (&observable, &observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.event_ptr_arg, &observer, 0, MOCK_ARG (arg));

	CuAssertIntEquals (test, 0, status);

	status = observable_notify_observers_with_ptr (&observable,
		offsetof (struct observer_mock, event_ptr_arg), arg);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&observer.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.event_ptr_arg, &observer, 0, MOCK_ARG (arg));

	CuAssertIntEquals (test, 0, status);

	status = observable_notify_observers_with_ptr (&observable,
		offsetof (struct observer_mock, event_ptr_arg), arg);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	observable_release (&observable);
}

static void observable_test_notify_observers_with_ptr_multiple_observers (CuTest *test)
{
	struct observer_mock observer1;
	struct observer_mock observer2;
	struct observer_mock observer3;
	struct observable observable;
	int status;
	void *arg = &status;

	TEST_START;

	status = observer_mock_init (&observer1);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_init (&observer2);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_init (&observer3);
	CuAssertIntEquals (test, 0, status);

	status = observable_init (&observable);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (&observable, &observer1);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (&observable, &observer2);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (&observable, &observer3);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer1.mock, observer1.event_ptr_arg, &observer1, 0, MOCK_ARG (arg));
	status |= mock_expect (&observer2.mock, observer2.event_ptr_arg, &observer2, 0, MOCK_ARG (arg));
	status |= mock_expect (&observer3.mock, observer3.event_ptr_arg, &observer3, 0, MOCK_ARG (arg));

	CuAssertIntEquals (test, 0, status);

	status = observable_notify_observers_with_ptr (&observable,
		offsetof (struct observer_mock, event_ptr_arg), arg);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_validate_and_release (&observer1);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_validate_and_release (&observer2);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_validate_and_release (&observer3);
	CuAssertIntEquals (test, 0, status);

	observable_release (&observable);
}

static void observable_test_notify_observers_with_ptr_no_event_handler (CuTest *test)
{
	struct observer_mock observer;
	struct observable observable;
	int status;
	void *arg = &status;

	TEST_START;

	status = observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	observer.event_ptr_arg = NULL;

	status = observable_init (&observable);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (&observable, &observer);
	CuAssertIntEquals (test, 0, status);

	status = observable_notify_observers_with_ptr (&observable,
		offsetof (struct observer_mock, event_ptr_arg), arg);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	observable_release (&observable);
}

static void observable_test_notify_observers_with_ptr_argument_null (CuTest *test)
{
	struct observer_mock observer;
	struct observable observable;
	int status;

	TEST_START;

	status = observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = observable_init (&observable);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (&observable, &observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.event_ptr_arg, &observer, 0, MOCK_ARG (NULL));

	CuAssertIntEquals (test, 0, status);

	status = observable_notify_observers_with_ptr (&observable,
		offsetof (struct observer_mock, event_ptr_arg), NULL);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	observable_release (&observable);
}

static void observable_test_notify_observers_with_ptr_null (CuTest *test)
{
	struct observer_mock observer;
	struct observable observable;
	int status;
	void *arg = &status;

	TEST_START;

	status = observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = observable_init (&observable);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (&observable, &observer);
	CuAssertIntEquals (test, 0, status);

	status = observable_notify_observers_with_ptr (NULL,
		offsetof (struct observer_mock, event_ptr_arg), arg);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	status = observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	observable_release (&observable);
}

static void observable_test_add_observer_same_twice (CuTest *test)
{
	struct observer_mock observer1;
	struct observer_mock observer2;
	struct observer_mock observer3;
	struct observable observable;
	int status;
	void *arg = &status;

	TEST_START;

	status = observer_mock_init (&observer1);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_init (&observer2);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_init (&observer3);
	CuAssertIntEquals (test, 0, status);

	status = observable_init (&observable);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (&observable, &observer1);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (&observable, &observer2);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (&observable, &observer3);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (&observable, &observer2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer1.mock, observer1.event_ptr_arg, &observer1, 0, MOCK_ARG (arg));
	status |= mock_expect (&observer2.mock, observer2.event_ptr_arg, &observer2, 0, MOCK_ARG (arg));
	status |= mock_expect (&observer3.mock, observer3.event_ptr_arg, &observer3, 0, MOCK_ARG (arg));

	CuAssertIntEquals (test, 0, status);

	status = observable_notify_observers_with_ptr (&observable,
		offsetof (struct observer_mock, event_ptr_arg), arg);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_validate_and_release (&observer1);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_validate_and_release (&observer2);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_validate_and_release (&observer3);
	CuAssertIntEquals (test, 0, status);

	observable_release (&observable);
}

static void observable_test_add_observer_null (CuTest *test)
{
	struct observer_mock observer;
	struct observable observable;
	int status;

	TEST_START;

	status = observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = observable_init (&observable);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (NULL, &observer);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	status = observable_add_observer (&observable, NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	status = observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	observable_release (&observable);
}

static void observable_test_remove_observer (CuTest *test)
{
	struct observer_mock observer1;
	struct observer_mock observer2;
	struct observer_mock observer3;
	struct observable observable;
	int status;
	void *arg = &status;

	TEST_START;

	status = observer_mock_init (&observer1);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_init (&observer2);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_init (&observer3);
	CuAssertIntEquals (test, 0, status);

	status = observable_init (&observable);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (&observable, &observer1);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (&observable, &observer2);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (&observable, &observer3);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer1.mock, observer1.event_ptr_arg, &observer1, 0, MOCK_ARG (arg));
	status |= mock_expect (&observer2.mock, observer2.event_ptr_arg, &observer2, 0, MOCK_ARG (arg));
	status |= mock_expect (&observer3.mock, observer3.event_ptr_arg, &observer3, 0, MOCK_ARG (arg));

	CuAssertIntEquals (test, 0, status);

	status = observable_notify_observers_with_ptr (&observable,
		offsetof (struct observer_mock, event_ptr_arg), arg);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&observer1.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&observer2.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&observer3.mock);
	CuAssertIntEquals (test, 0, status);

	status = observable_remove_observer (&observable, &observer2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer1.mock, observer1.event_ptr_arg, &observer1, 0, MOCK_ARG (arg));
	status |= mock_expect (&observer3.mock, observer3.event_ptr_arg, &observer3, 0, MOCK_ARG (arg));

	CuAssertIntEquals (test, 0, status);

	status = observable_notify_observers_with_ptr (&observable,
		offsetof (struct observer_mock, event_ptr_arg), arg);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_validate_and_release (&observer1);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_validate_and_release (&observer2);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_validate_and_release (&observer3);
	CuAssertIntEquals (test, 0, status);

	observable_release (&observable);
}

static void observable_test_remove_observer_only_one (CuTest *test)
{
	struct observer_mock observer;
	struct observable observable;
	int status;
	void *arg = &status;

	TEST_START;

	status = observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = observable_init (&observable);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (&observable, &observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.event_ptr_arg, &observer, 0, MOCK_ARG (arg));

	CuAssertIntEquals (test, 0, status);

	status = observable_notify_observers_with_ptr (&observable,
		offsetof (struct observer_mock, event_ptr_arg), arg);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&observer.mock);
	CuAssertIntEquals (test, 0, status);

	status = observable_remove_observer (&observable, &observer);
	CuAssertIntEquals (test, 0, status);

	status = observable_notify_observers_with_ptr (&observable,
		offsetof (struct observer_mock, event_ptr_arg), arg);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	observable_release (&observable);
}

static void observable_test_remove_observer_none (CuTest *test)
{
	struct observer_mock observer;
	struct observable observable;
	int status;
	void *arg = &status;

	TEST_START;

	status = observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = observable_init (&observable);
	CuAssertIntEquals (test, 0, status);

	status = observable_remove_observer (&observable, &observer);
	CuAssertIntEquals (test, 0, status);

	status = observable_notify_observers_with_ptr (&observable,
		offsetof (struct observer_mock, event_ptr_arg), arg);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	observable_release (&observable);
}

static void observable_test_remove_observer_not_registered (CuTest *test)
{
	struct observer_mock observer1;
	struct observer_mock observer2;
	struct observer_mock observer3;
	struct observer_mock observer4;
	struct observable observable;
	int status;
	void *arg = &status;

	TEST_START;

	status = observer_mock_init (&observer1);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_init (&observer2);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_init (&observer3);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_init (&observer4);
	CuAssertIntEquals (test, 0, status);

	status = observable_init (&observable);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (&observable, &observer1);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (&observable, &observer2);
	CuAssertIntEquals (test, 0, status);

	status = observable_add_observer (&observable, &observer3);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer1.mock, observer1.event_ptr_arg, &observer1, 0, MOCK_ARG (arg));
	status |= mock_expect (&observer2.mock, observer2.event_ptr_arg, &observer2, 0, MOCK_ARG (arg));
	status |= mock_expect (&observer3.mock, observer3.event_ptr_arg, &observer3, 0, MOCK_ARG (arg));

	CuAssertIntEquals (test, 0, status);

	status = observable_notify_observers_with_ptr (&observable,
		offsetof (struct observer_mock, event_ptr_arg), arg);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&observer1.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&observer2.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&observer3.mock);
	CuAssertIntEquals (test, 0, status);

	status = observable_remove_observer (&observable, &observer4);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer1.mock, observer1.event_ptr_arg, &observer1, 0, MOCK_ARG (arg));
	status |= mock_expect (&observer2.mock, observer2.event_ptr_arg, &observer2, 0, MOCK_ARG (arg));
	status |= mock_expect (&observer3.mock, observer3.event_ptr_arg, &observer3, 0, MOCK_ARG (arg));

	CuAssertIntEquals (test, 0, status);

	status = observable_notify_observers_with_ptr (&observable,
		offsetof (struct observer_mock, event_ptr_arg), arg);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_validate_and_release (&observer1);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_validate_and_release (&observer2);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_validate_and_release (&observer3);
	CuAssertIntEquals (test, 0, status);

	status = observer_mock_validate_and_release (&observer4);
	CuAssertIntEquals (test, 0, status);

	observable_release (&observable);
}

static void observable_test_remove_observer_null (CuTest *test)
{
	struct observer_mock observer;
	struct observable observable;
	int status;

	TEST_START;

	status = observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = observable_init (&observable);
	CuAssertIntEquals (test, 0, status);

	status = observable_remove_observer (NULL, &observer);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	status = observable_remove_observer (&observable, NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	status = observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	observable_release (&observable);
}


TEST_SUITE_START (observable);

TEST (observable_test_init);
TEST (observable_test_init_null);
TEST (observable_test_release_null);
TEST (observable_test_notify_observers_no_observers);
TEST (observable_test_notify_observers_one_observer);
TEST (observable_test_notify_observers_twice);
TEST (observable_test_notify_observers_multiple_observers);
TEST (observable_test_notify_observers_no_event_handler);
TEST (observable_test_notify_observers_null);
TEST (observable_test_notify_observers_with_ptr_no_observers);
TEST (observable_test_notify_observers_with_ptr_one_observer);
TEST (observable_test_notify_observers_with_ptr_twice);
TEST (observable_test_notify_observers_with_ptr_multiple_observers);
TEST (observable_test_notify_observers_with_ptr_no_event_handler);
TEST (observable_test_notify_observers_with_ptr_argument_null);
TEST (observable_test_notify_observers_with_ptr_null);
TEST (observable_test_add_observer_same_twice);
TEST (observable_test_add_observer_null);
TEST (observable_test_remove_observer);
TEST (observable_test_remove_observer_only_one);
TEST (observable_test_remove_observer_none);
TEST (observable_test_remove_observer_not_registered);
TEST (observable_test_remove_observer_null);

TEST_SUITE_END;
