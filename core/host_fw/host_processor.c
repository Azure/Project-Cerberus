// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "host_processor.h"
#include "common/observable.h"


/**
 * Initialize the common handling for host processors.
 *
 * @param host The host processor to initialize.
 * @param state Variable context the host processor.  This must be uninitialized.
 *
 * @return 0 if the host was initialized successfully or an error code.
 */
int host_processor_init (struct host_processor *host, struct host_processor_state *state)
{
	if (host == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	memset (host, 0, sizeof (struct host_processor));

	host->state = state;

	return host_processor_init_state (host);
}

/**
 * Initialize only the variable state for common host processor handling.  The rest of the instance
 * is assumed to already have been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param host The host processor that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int host_processor_init_state (const struct host_processor *host)
{
	if ((host == NULL) || (host->state == NULL)) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	memset (host->state, 0, sizeof (*host->state));

	return observable_init (&host->state->observable);
}

/**
 * Release the resources used by base host processor.
 *
 * @param host The host processor to release.
 */
void host_processor_release (const struct host_processor *host)
{
	if (host) {
		observable_release (&host->state->observable);
	}
}

/**
 * Set the port identifier for a host processor interface.
 *
 * @param host The host processor instance to configure.
 * @param port The port identifier to set.
 */
void host_processor_set_port (const struct host_processor *host, int port)
{
	if (host) {
		host->state->port = port;
	}
}

/**
 * Get the port identifier for a host processor interface.
 *
 * @param host The host processor instance to query.
 *
 * @return The port identifier or an error code.  Use ROT_IS_ERROR to check for errors.
 */
int host_processor_get_port (const struct host_processor *host)
{
	if (host) {
		return host->state->port;
	}
	else {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}
}

/**
 * Add an observer for host events.
 *
 * @param host The host processor to register with.
 * @param observer The observer to add.
 *
 * @return 0 if the observer was successfully added or an error code.
 */
int host_processor_add_observer (const struct host_processor *host,
	const struct host_processor_observer *observer)
{
	if (host == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return observable_add_observer (&host->state->observable, (void*) observer);
}

/**
 * Remove an observer from host events.
 *
 * @param host The host processor to deregister from.
 * @param observer The observer to remove.
 *
 * @return 0 if the observer was successfully removed or an error code.
 */
int host_processor_remove_observer (const struct host_processor *host,
	const struct host_processor_observer *observer)
{
	if (host == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return observable_remove_observer (&host->state->observable, (void*) observer);
}
