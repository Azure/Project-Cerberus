// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "common/observable.h"
#include "host_processor.h"


/**
 * Initialize the common handling for host processors.
 *
 * @param host The host processor to initialize.
 *
 * @return 0 if the host was initialized successfully or an error code.
 */
int host_processor_init (struct host_processor *host)
{
	if (host == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	memset (host, 0, sizeof (struct host_processor));

	return observable_init (&host->observable);
}

/**
 * Release the resources used by base host processor.
 *
 * @param host The host processor to release.
 */
void host_processor_release (struct host_processor *host)
{
	if (host) {
		observable_release (&host->observable);
	}
}

/**
 * Set the port identifier for a host processor interface.
 *
 * @param host The host processor instance to configure.
 * @param port The port identifier to set.
 */
void host_processor_set_port (struct host_processor *host, int port)
{
	if (host) {
		host->port = port;
	}
}

/**
 * Get the port identifier for a host processor interface.
 *
 * @param host The host processor instance to query.
 *
 * @return The port identifier or an error code.  Use ROT_IS_ERROR to check for errors.
 */
int host_processor_get_port (struct host_processor *host)
{
	if (host) {
		return host->port;
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
int host_processor_add_observer (struct host_processor *host,
	struct host_processor_observer *observer)
{
	if (host == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return observable_add_observer (&host->observable, observer);
}

/**
 * Remove an observer from host events.
 *
 * @param host The host processor to deregister from.
 * @param observer The observer to remove.
 *
 * @return 0 if the observer was successfully removed or an error code.
 */
int host_processor_remove_observer (struct host_processor *host,
	struct host_processor_observer *observer)
{
	if (host == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return observable_remove_observer (&host->observable, observer);
}
