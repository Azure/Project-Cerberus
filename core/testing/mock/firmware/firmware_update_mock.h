// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_UPDATE_MOCK_H_
#define FIRMWARE_UPDATE_MOCK_H_

#include "mock.h"
#include "firmware/firmware_update.h"


/**
 * A mock for a system firmware update.
 */
struct firmware_update_mock {
	struct firmware_update base;	/**< The base firmware update instance. */
	struct mock mock;				/**< The base mock instance. */
};


int firmware_update_mock_init (struct firmware_update_mock *mock,
	struct firmware_update_state *state, const struct firmware_flash_map *flash,
	const struct app_context *context, const struct firmware_image *fw,
	const struct security_manager *security, struct hash_engine *hash, int allowed_revision);
void firmware_update_mock_release (struct firmware_update_mock *mock);

int firmware_update_mock_validate_and_release (struct firmware_update_mock *mock);

int firmware_update_mock_finalize_image (const struct firmware_update *updater,
	const struct flash *flash, uint32_t address);
void firmware_update_mock_enable_finalize_image (struct firmware_update_mock *mock);

int firmware_update_mock_verify_boot_image (const struct firmware_update *updater,
	const struct flash *flash, uint32_t address);
void firmware_update_mock_enable_verify_boot_image (struct firmware_update_mock *mock);


#endif	/* FIRMWARE_UPDATE_MOCK_H_ */
