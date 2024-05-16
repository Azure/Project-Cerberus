// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_STATE_OBSERVER_DIRTY_RESET_H_
#define HOST_STATE_OBSERVER_DIRTY_RESET_H_

#include "host_control.h"
#include "host_state_observer.h"


/**
 * An observer for host state that will assert reset when the flash becomes dirty.
 */
struct host_state_observer_dirty_reset {
	struct host_state_observer base;	/**< Base observer instance. */
	const struct host_control *control;	/**< Interface to control the host reset signal. */
};


int host_state_observer_dirty_reset_init (struct host_state_observer_dirty_reset *observer,
	const struct host_control *control);
void host_state_observer_dirty_reset_release (struct host_state_observer_dirty_reset *observer);


#endif	/* HOST_STATE_OBSERVER_DIRTY_RESET_H_ */
