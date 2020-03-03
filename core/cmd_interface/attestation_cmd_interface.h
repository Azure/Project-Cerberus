// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ATTESTATION_CMD_INTERFACE_H_
#define ATTESTATION_CMD_INTERFACE_H_

#include <stdint.h>
#include "status/rot_status.h"


/**
 * Status codes for attestation operations. MAKE SURE IN SYNC WITH tools\cerberus_utility\cerberus_utility_commands.h!!
 */
enum attestation_cmd_status {
	ATTESTATION_CMD_STATUS_SUCCESS = 0,			/**< Successful operation. */
	ATTESTATION_CMD_STATUS_RUNNING,				/**< An attestation operation is in progress. */
	ATTESTATION_CMD_STATUS_FAILURE,				/**< Attestation operation failed. */
	ATTESTATION_CMD_STATUS_REQUEST_BLOCKED,		/**< A request has been made before the previous one finished. */
	ATTESTATION_CMD_STATUS_NONE_STARTED,		/**< No attestation operation has been started. */
	ATTESTATION_CMD_STATUS_TASK_NOT_RUNNING,	/**< The task servicing attestation operations is not running. */
	ATTESTATION_CMD_STATUS_UNKNOWN,				/**< The attestation status could not be determined. */
	ATTESTATION_CMD_STATUS_INTERNAL_ERROR,		/**< An unspecified, internal error occurred. */
};


#endif //ATTESTATION_CMD_INTERFACE_H_
