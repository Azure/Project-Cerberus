// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ERROR_STATE_ENTRY_INTERFACE_H_
#define ERROR_STATE_ENTRY_INTERFACE_H_

#include "logging/debug_log.h"
#include "status/rot_status.h"


/**
 * Interface to handle the module entering the error state for FIPS.
 */
struct error_state_entry_interface {
	/**
	 * Switch the module to the error state.  While in the error state, the module must not allow
	 * processing of any cryptographic operations.
	 *
	 * Depending on how the module implements error state handling, it's possible that this function
	 * may never return.
	 *
	 * This call must not fail.
	 *
	 * @param entry The handler for entering the error state.
	 * @param error_log An optional log message that should be saved to the debug log once it has
	 * been guaranteed that cryptographic operations have been halted.  Set this to null if there is
	 * no message that needs to be logged.  It's not necessary for every implementation to handle
	 * this data since some implementations may not have broader visibility to module state.
	 */
	void (*enter_error_state) (const struct error_state_entry_interface *entry,
		const struct debug_log_entry_info *error_log);
};


#define	ERROR_STATE_ENTRY_ERROR(code)		ROT_ERROR (ROT_MODULE_ERROR_STATE_ENTRY, code)

/**
 * Error codes that can be generated when entering the FIPS error state.
 */
enum {
	ERROR_STATE_ENTRY_INVALID_ARGUMENT = ERROR_STATE_ENTRY_ERROR (0x00),	/**< Input parameter is null or not valid. */
	ERROR_STATE_ENTRY_NO_MEMORY = ERROR_STATE_ENTRY_ERROR (0x01),			/**< Memory allocation failed. */
};


#endif	/* ERROR_STATE_ENTRY_INTERFACE_H_ */
