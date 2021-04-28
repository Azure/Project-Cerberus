// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SYSTEM_OBSERVER_STACK_USAGE_H_
#define SYSTEM_OBSERVER_STACK_USAGE_H_

#include "system/system_observer.h"


/**
 * Observer to dump stack usage on system resets.
 */
struct system_observer_stack_usage {
	struct system_observer base;			/**< Base observer instance. */
};


int system_observer_stack_usage_init (struct system_observer_stack_usage *stack);
void system_observer_stack_usage_release (struct system_observer_stack_usage *stack);


#endif /* SYSTEM_OBSERVER_STACK_USAGE_H_ */
