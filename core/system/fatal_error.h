// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FATAL_ERROR_H_
#define FATAL_ERROR_H_

#include "fatal_error_handler.h"


/**
 * Global singleton for the handler to call in response to fatal errors.
 */
#ifndef FATAL_ERROR_CONST_INSTANCE
extern const struct fatal_error_handler *fatal_error;
#else
extern const struct fatal_error_handler *const fatal_error;
#endif


void fatal_error_unrecoverable_error (int error_code);

void fatal_error_panic (int error_code, const struct debug_log_entry_info *error_log);
void fatal_error_panic_create_entry (int error_code, uint8_t severity, uint8_t component,
	uint8_t msg_index, uint32_t arg1, uint32_t arg2);


#endif	/* FATAL_ERROR_H_ */
