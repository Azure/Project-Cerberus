// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPI_FLASH_SFDP_TESTING_H_
#define SPI_FLASH_SFDP_TESTING_H_

#include <stdint.h>
#include <stddef.h>


#define	FLASH_ID_LEN	3

/* Macronix flash */

/* MX25L1606E */
extern const uint8_t FLASH_ID_MX25L1606E[];

extern const uint32_t SFDP_HEADER_MX25L1606E[];
extern const size_t SFDP_HEADER_MX25L1606E_LEN;

extern const uint32_t SFDP_PARAMS_ADDR_MX25L1606E;

extern const uint32_t SFDP_PARAMS_MX25L1606E[];
extern const size_t SFDP_PARAMS_MX25L1606E_LEN;

/* MX25L25635F */
extern const uint8_t FLASH_ID_MX25L25635F[];

extern const uint32_t SFDP_HEADER_MX25L25635F[];
extern const size_t SFDP_HEADER_MX25L25635F_LEN;

extern const uint32_t SFDP_PARAMS_ADDR_MX25L25635F;

extern const uint32_t SFDP_PARAMS_MX25L25635F[];
extern const size_t SFDP_PARAMS_MX25L25635F_LEN;

/* MX25L25645G */
extern const uint8_t FLASH_ID_MX25L25645G[];

extern const uint32_t SFDP_HEADER_MX25L25645G[];
extern const size_t SFDP_HEADER_MX25L25645G_LEN;

extern const uint32_t SFDP_PARAMS_ADDR_MX25L25645G;

extern const uint32_t SFDP_PARAMS_MX25L25645G[];
extern const size_t SFDP_PARAMS_MX25L25645G_LEN;


/* Winbond flash */

/* W25Q16JV */
extern const uint8_t FLASH_ID_W25Q16JV[];

extern const uint32_t SFDP_HEADER_W25Q16JV[];
extern const size_t SFDP_HEADER_W25Q16JV_LEN;

extern const uint32_t SFDP_PARAMS_ADDR_W25Q16JV;

extern const uint32_t SFDP_PARAMS_W25Q16JV[];
extern const size_t SFDP_PARAMS_W25Q16JV_LEN;

/* W25Q256JV */
extern const uint8_t FLASH_ID_W25Q256JV[];

extern const uint32_t SFDP_HEADER_W25Q256JV[];
extern const size_t SFDP_HEADER_W25Q256JV_LEN;

extern const uint32_t SFDP_PARAMS_ADDR_W25Q256JV;

extern const uint32_t SFDP_PARAMS_W25Q256JV[];
extern const size_t SFDP_PARAMS_W25Q256JV_LEN;


/* Micron flash */

/* MT25Q256ABA */
extern const uint8_t FLASH_ID_MT25Q256ABA[];

extern const uint32_t SFDP_HEADER_MT25Q256ABA[];
extern const size_t SFDP_HEADER_MT25Q256ABA_LEN;

extern const uint32_t SFDP_PARAMS_ADDR_MT25Q256ABA;

extern const uint32_t SFDP_PARAMS_MT25Q256ABA[];
extern const size_t SFDP_PARAMS_MT25Q256ABA_LEN;


/* Microchip flash */

/* SST26VF064B */
extern const uint8_t FLASH_ID_SST26VF064B[];

extern const uint32_t SFDP_HEADER_SST26VF064B[];
extern const size_t SFDP_HEADER_SST26VF064B_LEN;

extern const uint32_t SFDP_PARAMS_ADDR_SST26VF064B;

extern const uint32_t SFDP_PARAMS_SST26VF064B[];
extern const size_t SFDP_PARAMS_SST26VF064B_LEN;


#endif /* SPI_FLASH_SFDP_TESTING_H_ */
