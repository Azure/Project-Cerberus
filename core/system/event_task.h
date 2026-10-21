// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef EVENT_TASK_H_
#define EVENT_TASK_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "cmd_interface/cerberus_protocol.h"
#include "status/rot_status.h"


struct event_task_handler;

/**
 * The amount of data that can be stored in an event context for handling notifications.
 */
#define	EVENT_TASK_CONTEXT_BUFFER_LENGTH		MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY

/**
 * Execution context that can be used by event handlers.
 */
struct event_task_context {
	uint32_t action;										/**< An opaque identifier for the action to be performed. */
	size_t buffer_length;									/**< The amount of data contained in the event data buffer. */
	uint8_t event_buffer[EVENT_TASK_CONTEXT_BUFFER_LENGTH];	/**< Buffer for data that will processed by the event handler. */
};


/* event_buffer must be properly aligned in order to be able to cast it to specific type.
 * A better alternative is to use alignas(void*), but compiler support for that is unclear. */
_Static_assert (offsetof (struct event_task_context, event_buffer) % sizeof (void*) == 0,
	"event_task_context::event_buffer must be properly aligned");

/**
 * Interface to a task that executes operations based on external events.
 */
struct event_task {
	/**
	 * Lock the task mutex.  This call is the equivalent of calling platform_mutex_lock.
	 *
	 * @param task The task to lock.
	 *
	 * @return 0 if the mutex was locked or an error code.
	 */
	int (*lock) (const struct event_task *task);

	/**
	 * Unlock the task mutex.  This call is the equivalent of calling platform_mutex_unlock.
	 *
	 * @param task The task to unlock.
	 *
	 * @return 0 if the mutex was unlocked or an error code.
	 */
	int (*unlock) (const struct event_task *task);

	/**
	 * Get the event context for the task.  This is a structure shared with all handlers that
	 * execute in this task context.
	 *
	 * This function has the following properties:
	 * 		- If the event handler task has not been started, EVENT_TASK_NO_TASK will be returned.
	 * 		- If an event handler is actively running, EVENT_TASK_BUSY will be returned.
	 * 		- If task is available to handle an event, the context pointer will be returned and the
	 * 			task will be locked, just as if event_task.lock was called.
	 *
	 * Successful calls to event_task.get_event_context must be followed by a call to
	 * event_task.notify.
	 *
	 * @param task The task to query.
	 * @param context Output for the execution context for the task.  This pointer is owned by the
	 * task and must not be freed.
	 *
	 * @return 0 if the context is available for use or an error code.  If an error is returned, the
	 * context pointer will be set to null.
	 */
	int (*get_event_context) (const struct event_task *task, struct event_task_context **context);

	/**
	 * Notify the task of an event and indicate that some action needs to be performed.  It is
	 * expected that the event context has been correctly configured for event processing.
	 *
	 * This call will automatically unlock the task, just as if event_task.unlock was called.  The
	 * task will not be unlocked if EVENT_TASK_INVALID_ARGUMENT is returned.
	 *
	 * It is required that event_task.get_event_context be called prior to calling
	 * event_task.notify.  If event_task.get_event_context was not called, EVENT_TASK_NOT_READY will
	 * be returned.  A null handler can be used to cancel a previous call to
	 * event_task.get_event_context without triggering an event notification.  A null handler will
	 * generate an EVENT_TASK_UNKNOWN_HANDLER error.
	 *
	 * @param task The task to notify.
	 * @param handler The handler that needs to process the event.  Can be null to intentionally not
	 * trigger a notification to the task, but release the task for other use.
	 *
	 * @return 0 if the task was successfully notified or an error code.
	 */
	int (*notify) (const struct event_task *task, const struct event_task_handler *handler);
};

/**
 * Interface to a handler for executing actions from the task context.
 */
struct event_task_handler {
	/**
	 * Prepare an event handler to be ready to handle events.  This will get called once per handler
	 * once the task has been started and before it will process any event notifications.  This gets
	 * called from the context of the event handler task.
	 *
	 * This can be set to null if the handler does not require any preparation before handling
	 * received events.
	 *
	 * @param handler The handler being prepared for execution.  This will never be null.
	 */
	void (*prepare) (const struct event_task_handler *handler);

	/**
	 * Execute the specified action.  Pointers provided to this function will never be null.
	 *
	 * @param handler The handler executing the action.
	 * @param context Execution context to use during event processing.
	 * @param reset Output indicating whether the device needs to be reset or not as a result of the
	 * operation.  This will always be false at the time of execution and only needs to be updated
	 * if a reset is required.
	 */
	void (*execute) (const struct event_task_handler *handler, struct event_task_context *context,
		bool *reset);
};


void event_task_prepare_handlers (const struct event_task_handler *const *handlers, size_t count);
int event_task_find_handler (const struct event_task_handler *handler,
	const struct event_task_handler *const *list, size_t count);

int event_task_submit_event (const struct event_task *task,
	const struct event_task_handler *handler, uint32_t action, const uint8_t *data, size_t length,
	int starting_status, int *status_out);


#define	EVENT_TASK_ERROR(code)		ROT_ERROR (ROT_MODULE_EVENT_TASK, code)

/**
 * Error codes that can be generated by an event task.
 */
enum {
	EVENT_TASK_INVALID_ARGUMENT = EVENT_TASK_ERROR (0x00),		/**< Input parameter is null or not valid. */
	EVENT_TASK_NO_MEMORY = EVENT_TASK_ERROR (0x01),				/**< Memory allocation failed. */
	EVENT_TASK_LOCK_FAILED = EVENT_TASK_ERROR (0x02),			/**< Failure to lock the task. */
	EVENT_TASK_UNLOCK_FAILED = EVENT_TASK_ERROR (0x03),			/**< Failure to unlock the task. */
	EVENT_TASK_GET_CONTEXT_FAILED = EVENT_TASK_ERROR (0x04),	/**< Failure to retrieve the event context. */
	EVENT_TASK_NOTIFY_FAILED = EVENT_TASK_ERROR (0x05),			/**< Failure to notify the event handler. */
	EVENT_TASK_NO_TASK = EVENT_TASK_ERROR (0x06),				/**< The task has not been started. */
	EVENT_TASK_BUSY = EVENT_TASK_ERROR (0x07),					/**< The task is busy performing an operation. */
	EVENT_TASK_UNKNOWN_HANDLER = EVENT_TASK_ERROR (0x08),		/**< The handler is not known to the task. */
	EVENT_TASK_NOT_READY = EVENT_TASK_ERROR (0x09),				/**< The handler was not prepared to be notified. */
	EVENT_TASK_TOO_MUCH_DATA = EVENT_TASK_ERROR (0x0a),			/**< An event was submitted with too much data. */
};


#endif	/* EVENT_TASK_H_ */
