// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_PROCESSOR_SINGLE_FULL_BYPASS_STATIC_H_
#define HOST_PROCESSOR_SINGLE_FULL_BYPASS_STATIC_H_

#include "host_processor_single_full_bypass.h"
#include "host_processor_single_static.h"


/* Internal functions declared to allow for static initialization. */
int host_processor_single_full_bypass_enable_bypass_mode (
	const struct host_processor_filtered *host);


/**
 * Constant initializer for internal APIs.
 */
#define	HOST_PROCESSOR_SINGLE_FULL_BYPASS_INTERNAL_API_INIT	{ \
		.enable_bypass_mode = host_processor_single_full_bypass_enable_bypass_mode, \
		.prepare_verification = host_processor_single_prepare_verification, \
		.finalize_verification = host_processor_single_finalize_verification, \
	}


/**
 * Initialize a static instance of the interface for executing host processor actions using a single
 * flash device.  Unprotected flash will be accessible in full bypass mode.
 *
 * This does not initialize the handler state.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for host processor handling.
 * @param control_ptr The interface for controlling the host processor.
 * @param flash_ptr The manager for the flash device for the host processor.
 * @param host_state_ptr The state information for the host.
 * @param filter_ptr The SPI filter controlling flash access for the host processor.
 * @param pfm_ptr The manager for PFMs for the host processor.
 * @param recovery_ptr The manager for recovery of the host processor.
 */
#define	host_processor_single_full_bypass_static_init(state_ptr, control_ptr, flash_ptr, \
	host_state_ptr, filter_ptr, pfm_ptr, recovery_ptr)  \
		host_processor_single_static_init_internal (state_ptr, control_ptr, flash_ptr, \
			host_state_ptr, filter_ptr, pfm_ptr, recovery_ptr, 0, false, \
			HOST_PROCESSOR_SINGLE_FULL_BYPASS_INTERNAL_API_INIT)

/**
 * Initialize a static instance of the interface for executing host processor actions using a single
 * flash device.  Unprotected flash will be accessible in full bypass mode.
 *
 * While host flash is being accessed, the host processor will not be held in reset.  After the host
 * flash accesses have been completed, the host processor reset will be pulsed.
 *
 * This does not initialize the handler state.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for host processor handling.
 * @param control_ptr The interface for controlling the host processor.
 * @param flash_ptr The manager for the flash device for the host processor.
 * @param host_state_ptr The state information for the host.
 * @param filter_ptr The SPI filter controlling flash access for the host processor.
 * @param pfm_ptr The manager for PFMs for the host processor.
 * @param recovery_ptr The manager for recovery of the host processor.
 * @param pulse_width_arg The width of the reset pulse, in milliseconds.  If set to 0, the reset
 * will be held instead of being pulsed.
 */
#define	host_processor_single_full_bypass_static_init_pulse_reset(state_ptr, control_ptr, \
	flash_ptr, host_state_ptr, filter_ptr, pfm_ptr, recovery_ptr, pulse_width_arg)  \
		host_processor_single_static_init_internal (state_ptr, control_ptr, flash_ptr, \
			host_state_ptr, filter_ptr, pfm_ptr, recovery_ptr, pulse_width_arg, false, \
			HOST_PROCESSOR_SINGLE_FULL_BYPASS_INTERNAL_API_INIT)

/**
 * Initialize a static instance of the interface for executing host processor actions using a single
 * flash device.  Unprotected flash will be accessible in full bypass mode.
 *
 * The host flash device will be reset when the host resets.
 *
 * This does not initialize the handler state.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for host processor handling.
 * @param control_ptr The interface for controlling the host processor.
 * @param flash_ptr The manager for the flash device for the host processor.
 * @param host_state_ptr The state information for the host.
 * @param filter_ptr The SPI filter controlling flash access for the host processor.
 * @param pfm_ptr The manager for PFMs for the host processor.
 * @param recovery_ptr The manager for recovery of the host processor.
 */
#define	host_processor_single_full_bypass_static_init_reset_flash(state_ptr, control_ptr, \
	flash_ptr, host_state_ptr, filter_ptr, pfm_ptr, recovery_ptr)   \
		host_processor_single_static_init_internal (state_ptr, control_ptr, flash_ptr, \
			host_state_ptr, filter_ptr, pfm_ptr, recovery_ptr, 0, true, \
			HOST_PROCESSOR_SINGLE_FULL_BYPASS_INTERNAL_API_INIT)

/**
 * Initialize a static instance of the interface for executing host processor actions using a single
 * flash device.  Unprotected flash will be accessible in full bypass mode.
 *
 * While host flash is being accessed, the host processor will not be held in reset.  After the host
 * flash accesses have been completed, the host processor reset will be pulsed.
 *
 * The host flash device will be reset when the host resets.
 *
 * This does not initialize the handler state.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for host processor handling.
 * @param control_ptr The interface for controlling the host processor.
 * @param flash_ptr The manager for the flash device for the host processor.
 * @param host_state_ptr The state information for the host.
 * @param filter_ptr The SPI filter controlling flash access for the host processor.
 * @param pfm_ptr The manager for PFMs for the host processor.
 * @param recovery_ptr The manager for recovery of the host processor.
 * @param pulse_width_arg The width of the reset pulse, in milliseconds.  If set to 0, the reset
 * will be held instead of being pulsed.
 */
#define	host_processor_single_full_bypass_static_init_reset_flash_pulse_reset(state_ptr, \
	control_ptr, flash_ptr, host_state_ptr, filter_ptr, pfm_ptr, recovery_ptr, pulse_width_arg) \
		host_processor_single_static_init_internal (state_ptr, control_ptr, flash_ptr, \
			host_state_ptr, filter_ptr, pfm_ptr, recovery_ptr, pulse_width_arg, true, \
			HOST_PROCESSOR_SINGLE_FULL_BYPASS_INTERNAL_API_INIT)


#endif	/* HOST_PROCESSOR_SINGLE_FULL_BYPASS_STATIC_H_ */
