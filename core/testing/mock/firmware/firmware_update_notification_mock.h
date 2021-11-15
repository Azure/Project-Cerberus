// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_UPDATE_NOTIFICATION_MOCK_H_
#define FIRMWARE_UPDATE_NOTIFICATION_MOCK_H_

#include <stdint.h>
#include "firmware/firmware_update.h"
#include "mock.h"


/**
 * A mock handler for firmware update notifications.
 */
struct firmware_update_notification_mock {
	struct firmware_update_notification base;	/**< The base notification handlers. */
	struct mock mock;							/**< The base mock interface. */
};


int firmware_update_notification_mock_init (struct firmware_update_notification_mock *mock);
void firmware_update_notification_mock_release (struct firmware_update_notification_mock *mock);

int firmware_update_notification_mock_validate_and_release (
	struct firmware_update_notification_mock *mock);


#endif /* FIRMWARE_UPDATE_NOTIFICATION_MOCK_H_ */
