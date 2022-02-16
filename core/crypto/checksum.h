// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CHECKSUM_H_
#define CHECKSUM_H_

#include <stdint.h>


uint8_t checksum_crc8 (uint8_t smbus_addr, const uint8_t *data, uint8_t len);

uint8_t checksum_init_smbus_crc8 (uint8_t smbus_addr);
uint8_t checksum_update_smbus_crc8 (uint8_t crc, const uint8_t *data, uint8_t len);


#endif //CHECKSUM_H_
