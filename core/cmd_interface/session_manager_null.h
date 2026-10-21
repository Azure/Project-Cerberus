// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SESSION_MANAGER_NULL_H_
#define SESSION_MANAGER_NULL_H_

#include "session_manager.h"


/**
 * NULL object for session manager.
 */
struct session_manager_null {
	struct session_manager base;	/**< Base session manager. */
};


int session_manager_null_init (struct session_manager_null *session);
void session_manager_null_release (struct session_manager_null *session);


#endif	// SESSION_MANAGER_NULL_H_
