// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef TASK_PRIORITY_H_
#define TASK_PRIORITY_H_


/*
 * Cerberus task priorities.
 */

/** Priority of the idle task. */
#define	CERBERUS_PRIORITY_IDLE			0

/** Lowest priority background tasks. */
#define	CERBERUS_PRIORITY_BACKGROUND	1

/** Normal priority tasks. */
#define	CERBERUS_PRIORITY_NORMAL		2

/** High priority tasks. */
#define	CERBERUS_PRIORITY_HIGH			3

/** Highest priority tasks that need immediate servicing. */
#define	CERBERUS_PRIORITY_CRITICAL		4

/**
 * The minimum number of priority levels required.  This is not a valid priority level.
 */
#define	CERBERUS_PRIORITY_COUNT			5


#endif /* TASK_PRIORITY_H_ */
