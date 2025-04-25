// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ERROR_STATE_EXIT_INTERFACE_H_
#define ERROR_STATE_EXIT_INTERFACE_H_

#include "status/rot_status.h"


/**
 * Interface to handle the module exiting the error state for FIPS.
 */
struct error_state_exit_interface {
	/**
	 * Switch the module out of the error state.  Once out of the error state, cryptographic
	 * operations can resume.
	 *
	 * Depending on how the module implements error state handling, it's possible that this function
	 * may never return.
	 *
	 * @param exit The handler for exiting the error state.
	 *
	 * @return 0 if the switch out of the error state was successful or an error code.
	 */
	int (*exit_error_state) (const struct error_state_exit_interface *exit);
};


#define	ERROR_STATE_EXIT_ERROR(code)		ROT_ERROR (ROT_MODULE_ERROR_STATE_EXIT, code)

/**
 * Error codes that can be generated when exiting the FIPS error state.
 */
enum {
	ERROR_STATE_EXIT_INVALID_ARGUMENT = ERROR_STATE_EXIT_ERROR (0x00),	/**< Input parameter is null or not valid. */
	ERROR_STATE_EXIT_NO_MEMORY = ERROR_STATE_EXIT_ERROR (0x01),			/**< Memory allocation failed. */
	ERROR_STATE_EXIT_EXIT_FAILED = ERROR_STATE_EXIT_ERROR (0x02),		/**< Failed to exit the error state. */
};


#endif	/* ERROR_STATE_EXIT_INTERFACE_H_ */
