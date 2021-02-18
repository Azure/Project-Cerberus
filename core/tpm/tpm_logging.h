// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef TPM_LOGGING_H_
#define TPM_LOGGING_H_

#include "logging/debug_log.h"


/**
 * Logging messages for TPM.
 */
enum {
	TPM_LOGGING_CLEAR_FAILED,				/**< TPM clear failed. */
	TPM_LOGGING_CLEAR_TPM,					/**< TPM storage has been cleared. */
	TPM_LOGGING_INVALID_HEADER,				/**< TPM storage header was not valid. */
	TPM_LOGGING_READ_HEADER_FAILED,			/**< Failed to read the TPM header. */
	TPM_LOGGING_SOFT_RESET_ERROR,			/**< Error during reset processing. */
	TPM_LOGGING_NO_HEADER,					/**< TPM header not available. */
	TPM_LOGGING_NO_SEGMENT_DATA,			/**< TPM storage segment had no data. */
	TPM_LOGGING_ERASE_FAILED,				/**< TPM erase failed. */
};


#endif /* TPM_LOGGING_H_ */
