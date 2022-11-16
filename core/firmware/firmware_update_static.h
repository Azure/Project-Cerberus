// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_UPDATE_STATIC_H_
#define FIRMWARE_UPDATE_STATIC_H_

#include "firmware/firmware_update.h"


/**
 * Constant initializer for the internal update customization hooks.
 */
#define	FIRMWARE_UPDATE_INTERNAL_API_INIT  { \
		.finalize_image = NULL, \
		.verify_boot_image = NULL \
	}


/**
 * Initialize a static instance of a firmware updater.  This does not initialize the updater state.
 * This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the updater.
 * @param flash_ptr The device and address mapping for firmware images.
 * @param context_ptr The application context API.
 * @param fw_ptr The platform handler for firmware images.
 * @param hash_ptr The hash engine to use during updates.
 */
#define	firmware_update_static_init(state_ptr, flash_ptr, context_ptr, fw_ptr, hash_ptr)	{ \
		.internal = FIRMWARE_UPDATE_INTERNAL_API_INIT, \
		.state = state_ptr, \
		.flash = flash_ptr, \
		.fw = fw_ptr, \
		.hash = hash_ptr, \
		.context = context_ptr, \
		.no_fw_header = false \
	}

/**
 * Initialize a static instance of a firmware updater.  This does not initialize the updater state.
 * This can be a constant instance.
 *
 * Firmware images processed by the updater are not required to contain a firmware header.  If the
 * firmware header is present, it will be processed.  If the firmware header is not present, the
 * update will proceed without it and any workflows that required information from the header will
 * be skipped.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the updater.
 * @param flash_ptr The device and address mapping for firmware images.
 * @param context_ptr The application context API.
 * @param fw_ptr The platform handler for firmware images.
 * @param hash_ptr The hash engine to use during updates.
 */
#define	firmware_update_static_init_no_firmware_header(state_ptr, flash_ptr, context_ptr, fw_ptr, \
	hash_ptr)	{ \
		.internal = FIRMWARE_UPDATE_INTERNAL_API_INIT, \
		.state = state_ptr, \
		.flash = flash_ptr, \
		.fw = fw_ptr, \
		.hash = hash_ptr, \
		.context = context_ptr, \
		.no_fw_header = true \
	}


#endif /* FIRMWARE_UPDATE_STATIC_H_ */
