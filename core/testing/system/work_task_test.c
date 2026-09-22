// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "common/array_size.h"
#include "common/unused.h"
#include "system/work_task.h"
#include "system/work_task_static.h"
#include "testing/mock/system/work_task_handler_mock.h"


TEST_SUITE_LABEL ("work_task_interface");


/**
 * Dependencies for testing.
 */
struct work_task_testing {
	struct work_task_state state;			/**< Variable context for the queue. */
	struct work_task task;					/**< The work task under test. */
	struct work_task_handler_mock handler;	/**< A mock work handler. */
};

/**
 * A concrete handler used for scenarios the mock cannot express (re-submit from within execute,
 * observing queue state during execution).
 */
struct work_task_test_handler {
	struct work_task_handler base;							/**< Base handler interface. */
	struct work_task_entry *entry;							/**< Entry bound to this handler. */
	void *context;											/**< Context captured on the last execute(). */
	int executions;											/**< Number of times execute() has been called. */
	int resubmit;											/**< Remaining number of times to re-submit self. */
	const struct work_task_interface *owner_during_execute;	/**< Entry owner during execute(). */
};


static void work_task_test_handler_execute (const struct work_task_handler *handler,
	const struct work_task_interface *task, void *context)
{
	struct work_task_test_handler *test_handler = (struct work_task_test_handler*) handler;

	test_handler->executions++;
	test_handler->context = context;
	test_handler->owner_during_execute = test_handler->entry->owner;

	if (test_handler->resubmit > 0) {
		test_handler->resubmit--;
		task->submit (task, test_handler->entry, &test_handler->base, context);
	}
}

static void work_task_test_handler_init (struct work_task_test_handler *handler,
	struct work_task_entry *entry)
{
	memset (handler, 0, sizeof (*handler));
	handler->base.execute = work_task_test_handler_execute;
	handler->entry = entry;
}


/**
 * Records handler execution order so tests can assert interleaving across entries.
 */
struct work_task_order_log {
	int seq[32];	/**< Ordered list of handler markers. */
	int count;		/**< Number of markers recorded. */
};


static void work_task_order_log_add (struct work_task_order_log *log, int marker)
{
	if (log->count < (int) (sizeof (log->seq) / sizeof (log->seq[0]))) {
		log->seq[log->count++] = marker;
	}
}

/**
 * A trivial handler that records a fixed marker when it runs.  Used as the higher-priority "force"
 * work in preemption tests.
 */
struct work_task_marker_handler {
	struct work_task_handler base;		/**< Base handler interface. */
	struct work_task_order_log *log;	/**< Shared execution-order log. */
	int marker;							/**< Marker to record on execute. */
};


static void work_task_marker_handler_execute (const struct work_task_handler *handler,
	const struct work_task_interface *task, void *context)
{
	struct work_task_marker_handler *marker = (struct work_task_marker_handler*) handler;

	UNUSED (task);
	UNUSED (context);
	work_task_order_log_add (marker->log, marker->marker);
}

static void work_task_marker_handler_init (struct work_task_marker_handler *handler,
	struct work_task_order_log *log, int marker)
{
	memset (handler, 0, sizeof (*handler));
	handler->base.execute = work_task_marker_handler_execute;
	handler->log = log;
	handler->marker = marker;
}

/**
 * Simulates a periodic worker that processes a batch of "devices" one at a time within a single
 * execute() call.  After a configurable number of devices it submits a higher-priority entry (as if
 * a force request arrived), and it yields (re-arming itself) as soon as work_task_preempt_pending()
 * reports higher-priority work is ready.
 */
struct work_task_yield_handler {
	struct work_task_handler base;					/**< Base handler interface. */
	struct work_task_entry *entry;					/**< This handler's own entry. */
	struct work_task_order_log *log;				/**< Shared execution-order log. */
	int devices_total;								/**< Number of devices to process. */
	int devices_done;								/**< Devices processed so far. */
	int marker_offset;
	int inject_after;								/**< Submit the force entry after this many devices (0 = never). */
	struct work_task_entry *force_entry;			/**< Higher-priority entry to inject. */
	const struct work_task_handler *force_handler;	/**< Handler for the injected entry. */
	uint8_t force_priority;							/**< Priority for the injected entry. */
	bool injected;									/**< Whether the force entry has been submitted. */
	int yields;										/**< Number of times the handler yielded. */
};


static void work_task_yield_handler_execute (const struct work_task_handler *handler,
	const struct work_task_interface *task, void *context)
{
	struct work_task_yield_handler *yield = (struct work_task_yield_handler*) handler;

	UNUSED (context);

	while (yield->devices_done < yield->devices_total) {
		yield->devices_done++;
		work_task_order_log_add (yield->log, yield->marker_offset + yield->devices_done);

		/* Simulate a force request arriving mid-batch. */
		if (!yield->injected && (yield->inject_after != 0) &&
			(yield->devices_done == yield->inject_after)) {
			yield->injected = true;
			work_task_submit_with_priority (task, yield->force_entry, yield->force_handler,	NULL,
				yield->force_priority);
		}

		/* Yield to higher-priority work at the device boundary, re-arming to resume afterward. */
		if ((yield->devices_done < yield->devices_total) &&
			work_task_preempt_pending (task)) {
			yield->yields++;
			work_task_resubmit (task, yield->entry);

			return;
		}
	}
}

static void work_task_yield_handler_init (struct work_task_yield_handler *handler,
	struct work_task_entry *entry, struct work_task_order_log *log, int devices_total)
{
	memset (handler, 0, sizeof (*handler));
	handler->base.execute = work_task_yield_handler_execute;
	handler->entry = entry;
	handler->log = log;
	handler->devices_total = devices_total;
}

/**
 * Submits or schedules an extra entry from within execute(), then records what
 * work_task_preempt_pending() reports.  Used to unit-test the preemption predicate directly.
 */
struct work_task_observe_handler {
	struct work_task_handler base;					/**< Base handler interface. */
	struct work_task_entry *extra;					/**< Extra entry to enqueue during execute (may be null). */
	const struct work_task_handler *extra_handler;	/**< Handler for the extra entry. */
	uint8_t extra_priority;							/**< Priority for the extra entry. */
	bool extra_scheduled;							/**< Schedule the extra entry in the future instead of now. */
	bool preempt_observed;							/**< preempt_pending() result captured during execute. */
	const struct work_task_interface *extra_task;
	struct work_task_entry *ready_extra;
	bool cancel_extra;
	int setup_status;
};


static void work_task_observe_handler_execute (const struct work_task_handler *handler,
	const struct work_task_interface *task, void *context)
{
	struct work_task_observe_handler *observe = (struct work_task_observe_handler*) handler;
	const struct work_task_interface *destination =
		observe->extra_task ? observe->extra_task : task;

	UNUSED (context);

	if (observe->extra != NULL) {
		if (observe->extra_scheduled) {
			platform_clock deadline;

			observe->setup_status = platform_init_timeout (2000, &deadline);
			if (observe->setup_status != 0) {
				return;
			}
			observe->setup_status = work_task_schedule_with_priority (destination, observe->extra,
				observe->extra_handler,	NULL, &deadline, observe->extra_priority);
		}
		else {
			observe->setup_status = work_task_submit_with_priority (destination, observe->extra,
				observe->extra_handler,	NULL, observe->extra_priority);
		}
		if (observe->setup_status != 0) {
			return;
		}
		if (observe->cancel_extra) {
			observe->setup_status = destination->cancel (destination, observe->extra);
		}
		if ((observe->setup_status == 0) && (observe->ready_extra != NULL)) {
			observe->setup_status = work_task_submit_with_priority (task, observe->ready_extra,
				observe->extra_handler, NULL, observe->extra_priority - 1);
		}
	}

	observe->preempt_observed = work_task_preempt_pending (task);
}

static void work_task_observe_handler_init (struct work_task_observe_handler *handler)
{
	memset (handler, 0, sizeof (*handler));
	handler->base.execute = work_task_observe_handler_execute;
}

/**
 * A handler that, on its first execution, submits a competitor entry and then re-arms itself with
 * work_task_resubmit().  Used to prove the re-armed entry keeps its original priority.
 */
struct work_task_rearm_handler {
	struct work_task_handler base;						/**< Base handler interface. */
	struct work_task_entry *entry;						/**< This handler's own entry. */
	struct work_task_order_log *log;					/**< Shared execution-order log. */
	int marker;											/**< Marker recorded on each run. */
	struct work_task_entry *competitor;					/**< Competitor entry submitted on first run. */
	const struct work_task_handler *competitor_handler;	/**< Handler for the competitor entry. */
	uint8_t competitor_priority;						/**< Priority for the competitor entry. */
	int runs;											/**< Number of times executed. */
};


static void work_task_rearm_handler_execute (const struct work_task_handler *handler,
	const struct work_task_interface *task, void *context)
{
	struct work_task_rearm_handler *rearm = (struct work_task_rearm_handler*) handler;

	UNUSED (context);

	rearm->runs++;
	work_task_order_log_add (rearm->log, rearm->marker);

	if (rearm->runs == 1) {
		work_task_submit_with_priority (task, rearm->competitor, rearm->competitor_handler,	NULL,
			rearm->competitor_priority);
		work_task_resubmit (task, rearm->entry);
	}
}

static void work_task_rearm_handler_init (struct work_task_rearm_handler *handler,
	struct work_task_entry *entry, struct work_task_order_log *log, int marker)
{
	memset (handler, 0, sizeof (*handler));
	handler->base.execute = work_task_rearm_handler_execute;
	handler->entry = entry;
	handler->log = log;
	handler->marker = marker;
}


/**
 * Initialize the work task and handler mock under test.
 *
 * @param test The testing framework.
 * @param work The testing components to initialize.
 */
static void work_task_testing_init (CuTest *test, struct work_task_testing *work)
{
	int status;

	status = work_task_init (&work->task, &work->state);
	CuAssertIntEquals (test, 0, status);

	status = work_task_handler_mock_init (&work->handler);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Validate mocks and release the work task under test.
 *
 * @param test The testing framework.
 * @param work The testing components to release.
 */
static void work_task_testing_release (CuTest *test, struct work_task_testing *work)
{
	int status;

	status = work_task_handler_mock_validate_and_release (&work->handler);
	CuAssertIntEquals (test, 0, status);

	work_task_release (&work->task);
}


/*******************
 * Test cases
 *******************/

static void work_task_test_init (CuTest *test)
{
	struct work_task_state state;
	struct work_task task;
	int status;

	TEST_START;

	status = work_task_init (&task, &state);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, task.base.submit);
	CuAssertPtrNotNull (test, task.base.schedule);
	CuAssertPtrNotNull (test, task.base.cancel);

	work_task_release (&task);
}

static void work_task_test_init_null (CuTest *test)
{
	struct work_task_state state;
	struct work_task task;
	int status;

	TEST_START;

	status = work_task_init (NULL, &state);
	CuAssertIntEquals (test, WORK_TASK_INVALID_ARGUMENT, status);

	status = work_task_init (&task, NULL);
	CuAssertIntEquals (test, WORK_TASK_INVALID_ARGUMENT, status);
}

static void work_task_test_static_init (CuTest *test)
{
	struct work_task_state state;
	struct work_task task = work_task_static_init (&state);
	int status;

	TEST_START;

	CuAssertPtrEquals (test, work_task_submit, task.base.submit);
	CuAssertPtrEquals (test, work_task_schedule, task.base.schedule);
	CuAssertPtrEquals (test, work_task_cancel, task.base.cancel);

	status = work_task_init_state (&task);
	CuAssertIntEquals (test, 0, status);

	work_task_release (&task);
}

static void work_task_test_submit_and_run (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_entry entry = {0};
	int context = 5;
	bool executed = false;
	int status;

	TEST_START;

	work_task_testing_init (test, &work);

	status = work.task.base.submit (&work.task.base, &entry, &work.handler.base, &context);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&work.handler.mock, work.handler.base.execute, &work.handler, 0,
		MOCK_ARG_PTR (&work.task.base), MOCK_ARG_PTR (&context));
	CuAssertIntEquals (test, 0, status);

	status = work_task_run_next (&work.task, 100, &executed);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, true, executed);

	work_task_testing_release (test, &work);
}

static void work_task_test_shared_handler_receives_executing_task (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_state second_state;
	struct work_task second_task;
	struct work_task_entry first_entry = {0};
	struct work_task_entry second_entry = {0};
	int first_context = 1;
	int second_context = 2;
	bool executed = false;
	int status;

	TEST_START;

	work_task_testing_init (test, &work);
	status = work_task_init (&second_task, &second_state);
	CuAssertIntEquals (test, 0, status);

	status = work.task.base.submit (&work.task.base, &first_entry, &work.handler.base,
		&first_context);
	CuAssertIntEquals (test, 0, status);
	status = second_task.base.submit (&second_task.base, &second_entry, &work.handler.base,
		&second_context);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&work.handler.mock, work.handler.base.execute, &work.handler, 0,
		MOCK_ARG_PTR (&second_task.base), MOCK_ARG_PTR (&second_context));
	CuAssertIntEquals (test, 0, status);
	status = mock_expect (&work.handler.mock, work.handler.base.execute, &work.handler, 0,
		MOCK_ARG_PTR (&work.task.base), MOCK_ARG_PTR (&first_context));
	CuAssertIntEquals (test, 0, status);

	status = work_task_run_next (&second_task, 100, &executed);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, true, executed);
	status = work_task_run_next (&work.task, 100, &executed);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, true, executed);

	work_task_release (&second_task);
	work_task_testing_release (test, &work);
}

static void work_task_test_submit_fifo_order (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_entry entry1 = {0};
	struct work_task_entry entry2 = {0};
	int context1 = 1;
	int context2 = 2;
	bool executed = false;
	int status;

	TEST_START;

	work_task_testing_init (test, &work);

	status = work.task.base.submit (&work.task.base, &entry1, &work.handler.base, &context1);
	status |= work.task.base.submit (&work.task.base, &entry2, &work.handler.base, &context2);
	CuAssertIntEquals (test, 0, status);

	/* Expectations are ordered, so this asserts context1 runs before context2 (FIFO). */
	status = mock_expect (&work.handler.mock, work.handler.base.execute, &work.handler, 0,
		MOCK_ARG_PTR (&work.task.base), MOCK_ARG_PTR (&context1));
	status |= mock_expect (&work.handler.mock, work.handler.base.execute, &work.handler, 0,
		MOCK_ARG_PTR (&work.task.base), MOCK_ARG_PTR (&context2));
	CuAssertIntEquals (test, 0, status);

	status = work_task_run_next (&work.task, 100, &executed);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, true, executed);

	status = work_task_run_next (&work.task, 100, &executed);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, true, executed);

	work_task_testing_release (test, &work);
}

static void work_task_test_submit_null (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_entry entry = {0};
	int context = 0;
	int status;

	TEST_START;

	work_task_testing_init (test, &work);

	status = work.task.base.submit (NULL, &entry, &work.handler.base, &context);
	CuAssertIntEquals (test, WORK_TASK_INVALID_ARGUMENT, status);

	status = work.task.base.submit (&work.task.base, NULL, &work.handler.base, &context);
	CuAssertIntEquals (test, WORK_TASK_INVALID_ARGUMENT, status);

	status = work.task.base.submit (&work.task.base, &entry, NULL, &context);
	CuAssertIntEquals (test, WORK_TASK_INVALID_ARGUMENT, status);

	work_task_testing_release (test, &work);
}

static void work_task_test_submit_already_queued (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_entry entry = {0};
	struct work_task_handler_mock other;
	int context = 7;
	int other_context = 99;
	bool executed = false;
	int status;

	TEST_START;

	work_task_testing_init (test, &work);

	status = work_task_handler_mock_init (&other);
	CuAssertIntEquals (test, 0, status);

	status = work.task.base.submit (&work.task.base, &entry, &work.handler.base, &context);
	CuAssertIntEquals (test, 0, status);

	/* A second submit of the same pending entry is rejected and must NOT overwrite the binding. */
	status = work.task.base.submit (&work.task.base, &entry, &other.base, &other_context);
	CuAssertIntEquals (test, WORK_TASK_ALREADY_QUEUED, status);

	/* The original handler/context run, proving the rejected resubmit did not corrupt the entry. */
	status = mock_expect (&work.handler.mock, work.handler.base.execute, &work.handler, 0,
		MOCK_ARG_PTR (&work.task.base), MOCK_ARG_PTR (&context));
	CuAssertIntEquals (test, 0, status);

	status = work_task_run_next (&work.task, 100, &executed);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, true, executed);

	status = work_task_handler_mock_validate_and_release (&other);
	CuAssertIntEquals (test, 0, status);

	work_task_testing_release (test, &work);
}

static void work_task_test_entry_owner_lifecycle (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_entry entry = {0};
	int context = 0;
	bool executed = false;
	int status;

	TEST_START;

	work_task_testing_init (test, &work);

	CuAssertPtrEquals (test, NULL, entry.owner);

	status = work.task.base.submit (&work.task.base, &entry, &work.handler.base, &context);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &work.task.base, entry.owner);

	status = mock_expect (&work.handler.mock, work.handler.base.execute, &work.handler, 0,
		MOCK_ARG_PTR (&work.task.base), MOCK_ARG_PTR (&context));
	CuAssertIntEquals (test, 0, status);

	status = work_task_run_next (&work.task, 100, &executed);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, entry.owner);

	work_task_testing_release (test, &work);
}

static void work_task_test_cancel_pending (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_entry entry = {0};
	int context = 0;
	bool executed = true;
	int status;

	TEST_START;

	work_task_testing_init (test, &work);

	status = work.task.base.submit (&work.task.base, &entry, &work.handler.base, &context);
	CuAssertIntEquals (test, 0, status);

	status = work.task.base.cancel (&work.task.base, &entry);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, entry.owner);

	/* No handler should run; the queue is empty (run with a short bound, expect nothing). */
	status = work_task_run_next (&work.task, 10, &executed);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, executed);

	work_task_testing_release (test, &work);
}

static void work_task_test_cancel_not_queued (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_entry entry = {0};
	int status;

	TEST_START;

	work_task_testing_init (test, &work);

	status = work.task.base.cancel (&work.task.base, &entry);
	CuAssertIntEquals (test, WORK_TASK_NOT_QUEUED, status);

	work_task_testing_release (test, &work);
}

static void work_task_test_cancel_foreign_entry (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_state state2;
	struct work_task task2;
	struct work_task_entry entry = {0};
	int context = 0;
	bool executed = false;
	int status;

	TEST_START;

	work_task_testing_init (test, &work);

	status = work_task_init (&task2, &state2);
	CuAssertIntEquals (test, 0, status);

	/* Queue the entry on the first task, then try to cancel it through the second. */
	status = work.task.base.submit (&work.task.base, &entry, &work.handler.base, &context);
	CuAssertIntEquals (test, 0, status);

	status = task2.base.cancel (&task2.base, &entry);
	CuAssertIntEquals (test, WORK_TASK_FOREIGN_ENTRY, status);

	/* Still queued on the original task. */
	CuAssertPtrEquals (test, &work.task.base, entry.owner);

	status = mock_expect (&work.handler.mock, work.handler.base.execute, &work.handler, 0,
		MOCK_ARG_PTR (&work.task.base), MOCK_ARG_PTR (&context));
	CuAssertIntEquals (test, 0, status);

	status = work_task_run_next (&work.task, 100, &executed);
	CuAssertIntEquals (test, 0, status);

	work_task_release (&task2);
	work_task_testing_release (test, &work);
}

static void work_task_test_cancel_null (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_entry entry = {0};
	int status;

	TEST_START;

	work_task_testing_init (test, &work);

	status = work.task.base.cancel (NULL, &entry);
	CuAssertIntEquals (test, WORK_TASK_INVALID_ARGUMENT, status);

	status = work.task.base.cancel (&work.task.base, NULL);
	CuAssertIntEquals (test, WORK_TASK_INVALID_ARGUMENT, status);

	work_task_testing_release (test, &work);
}

static void work_task_test_schedule_future_not_ready (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_entry entry = {0};
	platform_clock deadline;
	int context = 0;
	bool executed = true;
	int status;

	TEST_START;

	work_task_testing_init (test, &work);

	status = platform_init_timeout (2000, &deadline);
	CuAssertIntEquals (test, 0, status);

	status = work.task.base.schedule (&work.task.base, &entry, &work.handler.base, &context,
		&deadline);
	CuAssertIntEquals (test, 0, status);

	/* The deadline is far out, so a short run does not execute the handler. */
	status = work_task_run_next (&work.task, 10, &executed);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, executed);

	/* Still queued. */
	CuAssertPtrEquals (test, &work.task.base, entry.owner);

	status = work.task.base.cancel (&work.task.base, &entry);
	CuAssertIntEquals (test, 0, status);

	work_task_testing_release (test, &work);
}

static void work_task_test_schedule_expired_runs (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_entry entry = {0};
	platform_clock deadline;
	int context = 0;
	bool executed = false;
	int status;

	TEST_START;

	work_task_testing_init (test, &work);

	/* A zero-millisecond deadline is already expired, so it is ready immediately. */
	status = platform_init_timeout (0, &deadline);
	CuAssertIntEquals (test, 0, status);

	status = work.task.base.schedule (&work.task.base, &entry, &work.handler.base, &context,
		&deadline);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&work.handler.mock, work.handler.base.execute, &work.handler, 0,
		MOCK_ARG_PTR (&work.task.base), MOCK_ARG_PTR (&context));
	CuAssertIntEquals (test, 0, status);

	status = work_task_run_next (&work.task, 100, &executed);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, true, executed);

	work_task_testing_release (test, &work);
}

static void work_task_test_schedule_null_deadline_is_immediate (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_entry entry = {0};
	int context = 0;
	bool executed = false;
	int status;

	TEST_START;

	work_task_testing_init (test, &work);

	status = work.task.base.schedule (&work.task.base, &entry, &work.handler.base, &context, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&work.handler.mock, work.handler.base.execute, &work.handler, 0,
		MOCK_ARG_PTR (&work.task.base), MOCK_ARG_PTR (&context));
	CuAssertIntEquals (test, 0, status);

	status = work_task_run_next (&work.task, 100, &executed);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, true, executed);

	work_task_testing_release (test, &work);
}

static void work_task_test_detached_during_execute (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_entry entry = {0};
	struct work_task_test_handler handler;
	int context = 0;
	bool executed = false;
	int status;

	TEST_START;

	work_task_testing_init (test, &work);
	work_task_test_handler_init (&handler, &entry);

	status = work.task.base.submit (&work.task.base, &entry, &handler.base, &context);
	CuAssertIntEquals (test, 0, status);

	status = work_task_run_next (&work.task, 100, &executed);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, true, executed);
	CuAssertIntEquals (test, 1, handler.executions);

	CuAssertPtrEquals (test, NULL, handler.owner_during_execute);

	work_task_testing_release (test, &work);
}

static void work_task_test_resubmit_self_from_execute (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_entry entry = {0};
	struct work_task_test_handler handler;
	int context = 0;
	bool executed = false;
	int status;

	TEST_START;

	work_task_testing_init (test, &work);
	work_task_test_handler_init (&handler, &entry);
	handler.resubmit = 1;	/* re-arm itself once from within execute() */

	status = work.task.base.submit (&work.task.base, &entry, &handler.base, &context);
	CuAssertIntEquals (test, 0, status);

	/* First run executes and re-submits. */
	status = work_task_run_next (&work.task, 100, &executed);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, true, executed);
	CuAssertIntEquals (test, 1, handler.executions);
	CuAssertPtrEquals (test, &work.task.base, entry.owner);

	/* Second run executes the re-submitted entry. */
	executed = false;
	status = work_task_run_next (&work.task, 100, &executed);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, true, executed);
	CuAssertIntEquals (test, 2, handler.executions);
	CuAssertPtrEquals (test, NULL, entry.owner);

	work_task_testing_release (test, &work);
}

static void work_task_test_submit_after (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_entry entry = {0};
	int context = 0;
	bool executed = true;
	int status;

	TEST_START;

	work_task_testing_init (test, &work);

	status = work_task_submit_after (&work.task.base, &entry, &work.handler.base, &context, 2000);
	CuAssertIntEquals (test, 0, status);

	/* Scheduled 2s out, so it is queued but not ready now. */
	CuAssertPtrEquals (test, &work.task.base, entry.owner);

	status = work_task_run_next (&work.task, 10, &executed);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, executed);

	status = work.task.base.cancel (&work.task.base, &entry);
	CuAssertIntEquals (test, 0, status);

	work_task_testing_release (test, &work);
}

static void work_task_test_submit_after_null (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_entry entry = {0};
	int context = 0;
	int status;

	TEST_START;

	work_task_testing_init (test, &work);

	status = work_task_submit_after (NULL, &entry, &work.handler.base, &context, 1000);
	CuAssertIntEquals (test, WORK_TASK_INVALID_ARGUMENT, status);

	work_task_testing_release (test, &work);
}

static void work_task_test_run_next_null (CuTest *test)
{
	int status;

	TEST_START;

	status = work_task_run_next (NULL, 100, NULL);
	CuAssertIntEquals (test, WORK_TASK_INVALID_ARGUMENT, status);
}

static void work_task_test_run_next_empty_queue (CuTest *test)
{
	struct work_task_testing work;
	bool executed = true;
	int status;

	TEST_START;

	work_task_testing_init (test, &work);

	status = work_task_run_next (&work.task, 10, &executed);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, executed);

	work_task_testing_release (test, &work);
}

static void work_task_test_submit_with_priority_order (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_entry low = {0};
	struct work_task_entry high = {0};
	int low_ctx = 1;
	int high_ctx = 2;
	bool executed = false;
	int status;

	TEST_START;

	work_task_testing_init (test, &work);

	/* Submit low priority first, then high; the higher priority must run first despite FIFO
	 * insertion order. */
	status = work_task_submit_with_priority (&work.task.base, &low, &work.handler.base, &low_ctx,
		1);
	status |= work_task_submit_with_priority (&work.task.base, &high, &work.handler.base, &high_ctx,
		5);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&work.handler.mock, work.handler.base.execute, &work.handler, 0,
		MOCK_ARG_PTR (&work.task.base), MOCK_ARG_PTR (&high_ctx));
	status |= mock_expect (&work.handler.mock, work.handler.base.execute, &work.handler, 0,
		MOCK_ARG_PTR (&work.task.base), MOCK_ARG_PTR (&low_ctx));
	CuAssertIntEquals (test, 0, status);

	status = work_task_run_next (&work.task, 100, &executed);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, true, executed);

	status = work_task_run_next (&work.task, 100, &executed);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, true, executed);

	work_task_testing_release (test, &work);
}

static void work_task_test_submit_with_priority_fifo_ties (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_entry entry1 = {0};
	struct work_task_entry entry2 = {0};
	int context1 = 1;
	int context2 = 2;
	bool executed = false;
	int status;

	TEST_START;

	work_task_testing_init (test, &work);

	/* Equal priority: insertion order (FIFO) breaks the tie. */
	status = work_task_submit_with_priority (&work.task.base, &entry1, &work.handler.base,
		&context1, 3);
	status |= work_task_submit_with_priority (&work.task.base, &entry2, &work.handler.base,
		&context2, 3);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&work.handler.mock, work.handler.base.execute, &work.handler, 0,
		MOCK_ARG_PTR (&work.task.base), MOCK_ARG_PTR (&context1));
	status |= mock_expect (&work.handler.mock, work.handler.base.execute, &work.handler, 0,
		MOCK_ARG_PTR (&work.task.base), MOCK_ARG_PTR (&context2));
	CuAssertIntEquals (test, 0, status);

	status = work_task_run_next (&work.task, 100, &executed);
	status |= work_task_run_next (&work.task, 100, &executed);
	CuAssertIntEquals (test, 0, status);

	work_task_testing_release (test, &work);
}

static void work_task_test_submit_with_priority_null (CuTest *test)
{
	struct work_task_entry entry = {0};
	int status;

	TEST_START;

	status = work_task_submit_with_priority (NULL, &entry, NULL, NULL, 0);
	CuAssertIntEquals (test, WORK_TASK_INVALID_ARGUMENT, status);
}

static void work_task_test_schedule_with_priority_expired_runs (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_entry entry = {0};
	platform_clock deadline;
	int context = 0;
	bool executed = false;
	int status;

	TEST_START;

	work_task_testing_init (test, &work);

	status = platform_init_timeout (0, &deadline);
	CuAssertIntEquals (test, 0, status);

	status = work_task_schedule_with_priority (&work.task.base, &entry, &work.handler.base,
		&context, &deadline, 4);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&work.handler.mock, work.handler.base.execute, &work.handler, 0,
		MOCK_ARG_PTR (&work.task.base), MOCK_ARG_PTR (&context));
	CuAssertIntEquals (test, 0, status);

	status = work_task_run_next (&work.task, 100, &executed);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, true, executed);

	work_task_testing_release (test, &work);
}

static void work_task_test_schedule_with_priority_null (CuTest *test)
{
	struct work_task_entry entry = {0};
	int status;

	TEST_START;

	status = work_task_schedule_with_priority (NULL, &entry, NULL, NULL, NULL, 0);
	CuAssertIntEquals (test, WORK_TASK_INVALID_ARGUMENT, status);
}

static void work_task_test_submit_after_with_priority (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_entry entry = {0};
	int context = 0;
	bool executed = true;
	int status;

	TEST_START;

	work_task_testing_init (test, &work);

	status = work_task_submit_after_with_priority (&work.task.base, &entry, &work.handler.base,
		&context, 2000, 3);
	CuAssertIntEquals (test, 0, status);

	/* Scheduled 2s out, so it is queued but not ready now. */
	CuAssertPtrEquals (test, &work.task.base, entry.owner);

	status = work_task_run_next (&work.task, 10, &executed);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, executed);

	status = work.task.base.cancel (&work.task.base, &entry);
	CuAssertIntEquals (test, 0, status);

	work_task_testing_release (test, &work);
}

static void work_task_test_submit_after_with_priority_null (CuTest *test)
{
	struct work_task_entry entry = {0};
	int status;

	TEST_START;

	status = work_task_submit_after_with_priority (NULL, &entry, NULL, NULL, 1000, 0);
	CuAssertIntEquals (test, WORK_TASK_INVALID_ARGUMENT, status);
}

static void work_task_test_resubmit_null (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_entry entry = {0};
	int status;

	TEST_START;

	work_task_testing_init (test, &work);

	status = work_task_resubmit (NULL, &entry);
	CuAssertIntEquals (test, WORK_TASK_INVALID_ARGUMENT, status);

	status = work_task_resubmit (&work.task.base, NULL);
	CuAssertIntEquals (test, WORK_TASK_INVALID_ARGUMENT, status);

	work_task_testing_release (test, &work);
}

static void work_task_test_preempt_pending_null (CuTest *test)
{
	TEST_START;

	CuAssertIntEquals (test, false, work_task_preempt_pending (NULL));
}

static void work_task_test_preempt_pending_idle_false (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_entry entry = {0};
	int context = 0;
	int status;

	TEST_START;

	work_task_testing_init (test, &work);

	/* No handler is running. */
	CuAssertIntEquals (test, false, work_task_preempt_pending (&work.task.base));

	/* Even with an entry queued, nothing is running, so there is nothing to preempt. */
	status = work_task_submit_with_priority (&work.task.base, &entry, &work.handler.base, &context,
		5);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, work_task_preempt_pending (&work.task.base));

	status = work.task.base.cancel (&work.task.base, &entry);
	CuAssertIntEquals (test, 0, status);

	work_task_testing_release (test, &work);
}

/**
 * Run a single observe handler at run_priority that injects an entry at inject_priority (optionally
 * scheduled into the future) during execute(), and return what preempt_pending() reported.
 */
enum work_task_preempt_scenario {
	WORK_TASK_PREEMPT_READY,
	WORK_TASK_PREEMPT_FUTURE,
	WORK_TASK_PREEMPT_CANCELLED,
	WORK_TASK_PREEMPT_OTHER_QUEUE,
	WORK_TASK_PREEMPT_MIXED,
};


static bool work_task_testing_observe_preempt (CuTest *test, struct work_task_testing *work,
	uint8_t run_priority, uint8_t inject_priority, enum work_task_preempt_scenario scenario)
{
	struct work_task_observe_handler observe;
	struct work_task_marker_handler injected;
	struct work_task_order_log log = {0};
	struct work_task_entry run_entry = {0};
	struct work_task_entry extra_entry = {0};
	struct work_task_entry ready_entry = {0};
	struct work_task_state other_state;
	struct work_task other_task;
	bool executed = false;
	int status;

	work_task_observe_handler_init (&observe);
	work_task_marker_handler_init (&injected, &log, 100);
	observe.extra = &extra_entry;
	observe.extra_handler = &injected.base;
	observe.extra_priority = inject_priority;
	observe.extra_scheduled = (scenario == WORK_TASK_PREEMPT_FUTURE) ||
		(scenario == WORK_TASK_PREEMPT_MIXED);
	observe.cancel_extra = (scenario == WORK_TASK_PREEMPT_CANCELLED);
	if (scenario == WORK_TASK_PREEMPT_OTHER_QUEUE) {
		status = work_task_init (&other_task, &other_state);
		CuAssertIntEquals (test, 0, status);
		observe.extra_task = &other_task.base;
	}
	if (scenario == WORK_TASK_PREEMPT_MIXED) {
		observe.ready_extra = &ready_entry;
	}

	status = work_task_submit_with_priority (&work->task.base, &run_entry, &observe.base, NULL,
		run_priority);
	CuAssertIntEquals (test, 0, status);

	status = work_task_run_next (&work->task, 100, &executed);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, true, executed);

	/* The injected entry never ran; remove it from the queue. */
	CuAssertIntEquals (test, 0, observe.setup_status);
	if (scenario == WORK_TASK_PREEMPT_OTHER_QUEUE) {
		status = other_task.base.cancel (&other_task.base, &extra_entry);
		CuAssertIntEquals (test, 0, status);
		work_task_release (&other_task);
	}
	else if (scenario != WORK_TASK_PREEMPT_CANCELLED) {
		status = work->task.base.cancel (&work->task.base, &extra_entry);
		CuAssertIntEquals (test, 0, status);
	}
	if (scenario == WORK_TASK_PREEMPT_MIXED) {
		status = work->task.base.cancel (&work->task.base, &ready_entry);
		CuAssertIntEquals (test, 0, status);
	}

	return observe.preempt_observed;
}

static void work_task_test_preempt_pending_higher_true (CuTest *test)
{
	struct work_task_testing work;

	TEST_START;

	work_task_testing_init (test, &work);

	/* Running at priority 0, a ready priority-5 entry appears: preemption is warranted. */
	CuAssertIntEquals (test, true,
		work_task_testing_observe_preempt (test, &work, 0, 5, WORK_TASK_PREEMPT_READY));

	work_task_testing_release (test, &work);
}

static void work_task_test_preempt_pending_equal_false (CuTest *test)
{
	struct work_task_testing work;

	TEST_START;

	work_task_testing_init (test, &work);

	/* Equal priority does not preempt (strictly higher is required). */
	CuAssertIntEquals (test, false,
		work_task_testing_observe_preempt (test, &work, 3, 3, WORK_TASK_PREEMPT_READY));

	work_task_testing_release (test, &work);
}

static void work_task_test_preempt_pending_lower_false (CuTest *test)
{
	struct work_task_testing work;

	TEST_START;

	work_task_testing_init (test, &work);

	/* A lower-priority pending entry never preempts. */
	CuAssertIntEquals (test, false,
		work_task_testing_observe_preempt (test, &work, 3, 1, WORK_TASK_PREEMPT_READY));

	work_task_testing_release (test, &work);
}

static void work_task_test_preempt_pending_future_higher_false (CuTest *test)
{
	struct work_task_testing work;

	TEST_START;

	work_task_testing_init (test, &work);

	/* A higher-priority entry that is not yet due must not preempt until its deadline. */
	CuAssertIntEquals (test, false,
		work_task_testing_observe_preempt (test, &work, 0, 5, WORK_TASK_PREEMPT_FUTURE));

	work_task_testing_release (test, &work);
}

static void work_task_test_preempt_pending_cancelled_false (CuTest *test)
{
	struct work_task_testing work;

	TEST_START;

	work_task_testing_init (test, &work);
	CuAssertIntEquals (test, false,
		work_task_testing_observe_preempt (test, &work, 0, 5, WORK_TASK_PREEMPT_CANCELLED));
	work_task_testing_release (test, &work);
}

static void work_task_test_preempt_pending_other_queue_false (CuTest *test)
{
	struct work_task_testing work;

	TEST_START;

	work_task_testing_init (test, &work);
	CuAssertIntEquals (test, false,
		work_task_testing_observe_preempt (test, &work, 0, 5, WORK_TASK_PREEMPT_OTHER_QUEUE));
	work_task_testing_release (test, &work);
}

static void work_task_test_preempt_pending_ready_behind_future_true (CuTest *test)
{
	struct work_task_testing work;

	TEST_START;

	work_task_testing_init (test, &work);
	CuAssertIntEquals (test, true,
		work_task_testing_observe_preempt (test, &work, 0, 5, WORK_TASK_PREEMPT_MIXED));
	work_task_testing_release (test, &work);
}

static void work_task_test_resubmit_preserves_priority (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_rearm_handler rearm;
	struct work_task_marker_handler competitor;
	struct work_task_order_log log = {0};
	struct work_task_entry rearm_entry = {0};
	struct work_task_entry competitor_entry = {0};
	bool executed = false;
	int status;
	int i;

	TEST_START;

	work_task_testing_init (test, &work);
	work_task_rearm_handler_init (&rearm, &rearm_entry, &log, 10);
	work_task_marker_handler_init (&competitor, &log, 20);
	rearm.competitor = &competitor_entry;
	rearm.competitor_handler = &competitor.base;
	rearm.competitor_priority = 3;

	/* Submit the re-arming entry at priority 5.  On its first run it submits a priority-3 competitor
	 * and re-arms itself; if resubmit preserves priority 5, the re-armed entry runs before the
	 * competitor. */
	status = work_task_submit_with_priority (&work.task.base, &rearm_entry, &rearm.base, NULL, 5);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 10; i++) {
		status = work_task_run_next (&work.task, 10, &executed);
		CuAssertIntEquals (test, 0, status);
		if (!executed) {
			break;
		}
	}

	/* Order proves the re-armed priority-5 entry (10) ran again before the priority-3 competitor
	 * (20). */
	CuAssertIntEquals (test, 3, log.count);
	CuAssertIntEquals (test, 10, log.seq[0]);
	CuAssertIntEquals (test, 10, log.seq[1]);
	CuAssertIntEquals (test, 20, log.seq[2]);

	work_task_testing_release (test, &work);
}

static void work_task_test_force_after_final_device_no_requeue (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_yield_handler periodic;
	struct work_task_marker_handler force;
	struct work_task_order_log log = {0};
	struct work_task_entry periodic_entry = {0};
	struct work_task_entry force_entry = {0};
	bool executed = false;
	int status;
	int i;

	TEST_START;

	work_task_testing_init (test, &work);
	work_task_yield_handler_init (&periodic, &periodic_entry, &log, 5);
	work_task_marker_handler_init (&force, &log, 100);

	periodic.inject_after = 5;
	periodic.force_entry = &force_entry;
	periodic.force_handler = &force.base;
	periodic.force_priority = 5;

	status = work_task_submit_with_priority (&work.task.base, &periodic_entry, &periodic.base, NULL,
		0);
	CuAssertIntEquals (test, 0, status);

	/* Drive the worker until the queue drains (bounded to avoid an infinite loop on regression). */
	for (i = 0; i < 10; i++) {
		status = work_task_run_next (&work.task, 10, &executed);
		CuAssertIntEquals (test, 0, status);
		if (!executed) {
			break;
		}
	}

	CuAssertIntEquals (test, 0, periodic.yields);
	CuAssertIntEquals (test, 2, i);
	CuAssertIntEquals (test, 5, periodic.devices_done);
	CuAssertIntEquals (test, 6, log.count);
	CuAssertIntEquals (test, 1, log.seq[0]);
	CuAssertIntEquals (test, 2, log.seq[1]);
	CuAssertIntEquals (test, 3, log.seq[2]);
	CuAssertIntEquals (test, 4, log.seq[3]);
	CuAssertIntEquals (test, 5, log.seq[4]);
	CuAssertIntEquals (test, 100, log.seq[5]);

	work_task_testing_release (test, &work);
}

static void work_task_test_periodic_debug_force_yield_and_resume (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_yield_handler periodic;
	struct work_task_yield_handler debug;
	struct work_task_marker_handler force;
	struct work_task_order_log log = {0};
	struct work_task_entry periodic_entry = {0};
	struct work_task_entry debug_entry = {0};
	struct work_task_entry force_entry = {0};
	const int expected[] = {1, 2, 11, 100, 12, 3, 4, 5};
	bool executed = false;
	int status;
	size_t index;

	TEST_START;

	work_task_testing_init (test, &work);
	work_task_yield_handler_init (&periodic, &periodic_entry, &log, 5);
	work_task_yield_handler_init (&debug, &debug_entry, &log, 2);
	debug.marker_offset = 10;
	work_task_marker_handler_init (&force, &log, 100);
	periodic.inject_after = 2;
	periodic.force_entry = &debug_entry;
	periodic.force_handler = &debug.base;
	periodic.force_priority = 3;
	debug.inject_after = 1;
	debug.force_entry = &force_entry;
	debug.force_handler = &force.base;
	debug.force_priority = 5;

	status = work_task_submit_with_priority (&work.task.base, &periodic_entry, &periodic.base, NULL,
		0);
	CuAssertIntEquals (test, 0, status);

	for (index = 0; index < 5; index++) {
		status = work_task_run_next (&work.task, 10, &executed);
		CuAssertIntEquals (test, 0, status);
		CuAssertIntEquals (test, true, executed);
	}

	CuAssertIntEquals (test, 1, periodic.yields);
	CuAssertIntEquals (test, 1, debug.yields);
	CuAssertIntEquals (test, 5, periodic.devices_done);
	CuAssertIntEquals (test, 2, debug.devices_done);
	CuAssertIntEquals (test, ARRAY_SIZE (expected), log.count);
	for (index = 0; index < ARRAY_SIZE (expected); index++) {
		CuAssertIntEquals (test, expected[index], log.seq[index]);
	}
	CuAssertPtrEquals (test, NULL, work.state.head);
	CuAssertPtrEquals (test, NULL, work.state.running_entry);

	work_task_testing_release (test, &work);
}

static void work_task_test_init_state_null (CuTest *test)
{
	struct work_task task;

	TEST_START;

	CuAssertIntEquals (test, WORK_TASK_INVALID_ARGUMENT, work_task_init_state (NULL));

	/* Instance present but with a null state pointer. */
	memset (&task, 0, sizeof (task));
	task.state = NULL;
	CuAssertIntEquals (test, WORK_TASK_INVALID_ARGUMENT, work_task_init_state (&task));
}

static void work_task_test_release_null (CuTest *test)
{
	TEST_START;

	/* Releasing a null queue must be a safe no-op. */
	work_task_release (NULL);
}

static void work_task_test_release_detaches_pending_entries (CuTest *test)
{
	struct work_task_state first_state;
	struct work_task_state second_state;
	struct work_task first_task;
	struct work_task second_task;
	struct work_task_handler_mock handler;
	struct work_task_entry entry = {0};
	int context = 0;
	int status;

	TEST_START;

	status = work_task_init (&first_task, &first_state);
	CuAssertIntEquals (test, 0, status);
	status = work_task_init (&second_task, &second_state);
	CuAssertIntEquals (test, 0, status);
	status = work_task_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = first_task.base.submit (&first_task.base, &entry, &handler.base, &context);
	CuAssertIntEquals (test, 0, status);

	work_task_release (&first_task);

	CuAssertPtrEquals (test, NULL, entry.owner);
	CuAssertPtrEquals (test, NULL, entry.next);
	status = second_task.base.submit (&second_task.base, &entry, &handler.base, &context);
	CuAssertIntEquals (test, 0, status);
	status = second_task.base.cancel (&second_task.base, &entry);
	CuAssertIntEquals (test, 0, status);

	status = work_task_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);
	work_task_release (&second_task);
}

static void work_task_test_run_next_executed_null (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_entry entry = {0};
	int context = 0;
	int status;

	TEST_START;

	work_task_testing_init (test, &work);

	status = work.task.base.submit (&work.task.base, &entry, &work.handler.base, &context);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&work.handler.mock, work.handler.base.execute, &work.handler, 0,
		MOCK_ARG_PTR (&work.task.base), MOCK_ARG_PTR (&context));
	CuAssertIntEquals (test, 0, status);

	/* A null executed output pointer must be accepted and the entry still run. */
	status = work_task_run_next (&work.task, 100, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, entry.owner);

	work_task_testing_release (test, &work);
}

static void work_task_test_cancel_middle_of_queue (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_entry entry1 = {0};
	struct work_task_entry entry2 = {0};
	struct work_task_entry entry3 = {0};
	int context1 = 1;
	int context2 = 2;
	int context3 = 3;
	bool executed = false;
	int status;

	TEST_START;

	work_task_testing_init (test, &work);

	status = work.task.base.submit (&work.task.base, &entry1, &work.handler.base, &context1);
	status |= work.task.base.submit (&work.task.base, &entry2, &work.handler.base, &context2);
	status |= work.task.base.submit (&work.task.base, &entry3, &work.handler.base, &context3);
	CuAssertIntEquals (test, 0, status);

	/* Cancel the middle entry; the list linkage around it must stay intact. */
	status = work.task.base.cancel (&work.task.base, &entry2);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, entry2.owner);
	CuAssertPtrEquals (test, &work.task.base, entry1.owner);
	CuAssertPtrEquals (test, &work.task.base, entry3.owner);

	/* Only entry1 then entry3 run, in FIFO order; the cancelled entry2 never runs. */
	status = mock_expect (&work.handler.mock, work.handler.base.execute, &work.handler, 0,
		MOCK_ARG_PTR (&work.task.base), MOCK_ARG_PTR (&context1));
	status |= mock_expect (&work.handler.mock, work.handler.base.execute, &work.handler, 0,
		MOCK_ARG_PTR (&work.task.base), MOCK_ARG_PTR (&context3));
	CuAssertIntEquals (test, 0, status);

	status = work_task_run_next (&work.task, 100, &executed);
	status |= work_task_run_next (&work.task, 100, &executed);
	CuAssertIntEquals (test, 0, status);

	work_task_testing_release (test, &work);
}

static void work_task_test_priority_outranks_ready_deadline (CuTest *test)
{
	struct work_task_testing work;
	struct work_task_entry immediate = {0};
	struct work_task_entry scheduled = {0};
	platform_clock deadline;
	int immediate_ctx = 1;
	int scheduled_ctx = 2;
	bool executed = false;
	int status;

	TEST_START;

	work_task_testing_init (test, &work);

	/* A low-priority immediate entry and a higher-priority already-expired scheduled entry are both
	 * ready; priority must win regardless of the scheduled/immediate distinction. */
	status = platform_init_timeout (0, &deadline);
	CuAssertIntEquals (test, 0, status);

	status = work_task_submit_with_priority (&work.task.base, &immediate, &work.handler.base,
		&immediate_ctx, 1);
	status |= work_task_schedule_with_priority (&work.task.base, &scheduled, &work.handler.base,
		&scheduled_ctx, &deadline, 5);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&work.handler.mock, work.handler.base.execute, &work.handler, 0,
		MOCK_ARG_PTR (&work.task.base), MOCK_ARG_PTR (&scheduled_ctx));
	status |= mock_expect (&work.handler.mock, work.handler.base.execute, &work.handler, 0,
		MOCK_ARG_PTR (&work.task.base), MOCK_ARG_PTR (&immediate_ctx));
	CuAssertIntEquals (test, 0, status);

	status = work_task_run_next (&work.task, 100, &executed);
	status |= work_task_run_next (&work.task, 100, &executed);
	CuAssertIntEquals (test, 0, status);

	work_task_testing_release (test, &work);
}


TEST_SUITE_START (work_task_interface);

TEST (work_task_test_init);
TEST (work_task_test_init_null);
TEST (work_task_test_static_init);
TEST (work_task_test_submit_and_run);
TEST (work_task_test_shared_handler_receives_executing_task);
TEST (work_task_test_submit_fifo_order);
TEST (work_task_test_submit_null);
TEST (work_task_test_submit_already_queued);
TEST (work_task_test_entry_owner_lifecycle);
TEST (work_task_test_cancel_pending);
TEST (work_task_test_cancel_not_queued);
TEST (work_task_test_cancel_foreign_entry);
TEST (work_task_test_cancel_null);
TEST (work_task_test_schedule_future_not_ready);
TEST (work_task_test_schedule_expired_runs);
TEST (work_task_test_schedule_null_deadline_is_immediate);
TEST (work_task_test_detached_during_execute);
TEST (work_task_test_resubmit_self_from_execute);
TEST (work_task_test_submit_after);
TEST (work_task_test_submit_after_null);
TEST (work_task_test_run_next_null);
TEST (work_task_test_run_next_empty_queue);
TEST (work_task_test_submit_with_priority_order);
TEST (work_task_test_submit_with_priority_fifo_ties);
TEST (work_task_test_submit_with_priority_null);
TEST (work_task_test_schedule_with_priority_expired_runs);
TEST (work_task_test_schedule_with_priority_null);
TEST (work_task_test_submit_after_with_priority);
TEST (work_task_test_submit_after_with_priority_null);
TEST (work_task_test_resubmit_null);
TEST (work_task_test_preempt_pending_null);
TEST (work_task_test_preempt_pending_idle_false);
TEST (work_task_test_preempt_pending_higher_true);
TEST (work_task_test_preempt_pending_equal_false);
TEST (work_task_test_preempt_pending_lower_false);
TEST (work_task_test_preempt_pending_future_higher_false);
TEST (work_task_test_preempt_pending_cancelled_false);
TEST (work_task_test_preempt_pending_other_queue_false);
TEST (work_task_test_preempt_pending_ready_behind_future_true);
TEST (work_task_test_resubmit_preserves_priority);
TEST (work_task_test_force_after_final_device_no_requeue);
TEST (work_task_test_periodic_debug_force_yield_and_resume);
TEST (work_task_test_init_state_null);
TEST (work_task_test_release_null);
TEST (work_task_test_release_detaches_pending_entries);
TEST (work_task_test_run_next_executed_null);
TEST (work_task_test_cancel_middle_of_queue);
TEST (work_task_test_priority_outranks_ready_deadline);

TEST_SUITE_END;
