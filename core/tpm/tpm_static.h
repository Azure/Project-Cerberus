// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef TPM_STATIC_H_
#define TPM_STATIC_H_

#include "tpm.h"

/* Internal functions declared to allow for static initialization. */
void tpm_on_soft_reset (struct host_processor_observer *observer);

/**
 * Constant initializer for TPM observer
 */
#define TPM_OBSERVER_API_INIT {         \
	.on_soft_reset = tpm_on_soft_reset, \
	.on_bypass_mode = NULL,             \
	.on_active_mode = NULL,             \
	.on_recovery = NULL                 \
}

/**
 * Initialize a static instance of a TPM.
 * There is no validation done on the arguments.
 * User should call tpm_init_state to complete initialization.
 *
 * @param flash_base The flash device where TPM storage is stored.
 * @param segment_storage_ptr The buffer for TPM storage.
 * @param sz The size of the TPM storage segment.
 */
#define tpm_static_init(flash_base, segment_storage_ptr, sz)    \
	{                                                           \
		.flash = flash_base,                                    \
		.segment_storage_size = sz,                             \
		.buffer = segment_storage_ptr,                          \
		.observer = TPM_OBSERVER_API_INIT                       \
	}


#endif	// TPM_STATIC_H_
