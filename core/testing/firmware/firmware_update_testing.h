// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_UPDATE_TESTING_H_
#define FIRMWARE_UPDATE_TESTING_H_

#include <stdint.h>
#include "testing.h"
#include "firmware/firmware_header.h"
#include "testing/mock/flash/flash_mock.h"


void firmware_update_testing_init_firmware_header (CuTest *test, struct firmware_header *header,
	struct flash_mock *flash, int id);
int firmware_update_testing_flash_page_size (struct flash_mock *flash, uint32_t page);


#endif /* FIRMWARE_UPDATE_TESTING_H_ */
