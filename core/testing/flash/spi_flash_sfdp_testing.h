// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPI_FLASH_SFDP_TESTING_H_
#define SPI_FLASH_SFDP_TESTING_H_

#include <stddef.h>
#include <stdint.h>


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

/* MX25L51245G */
extern const uint8_t FLASH_ID_MX25L51245G[];

extern const uint32_t SFDP_HEADER_MX25L51245G[];
extern const size_t SFDP_HEADER_MX25L51245G_LEN;

extern const uint32_t SFDP_PARAMS_ADDR_MX25L51245G;

extern const uint32_t SFDP_PARAMS_MX25L51245G[];
extern const size_t SFDP_PARAMS_MX25L51245G_LEN;

/* MX25U51245G */
extern const uint8_t FLASH_ID_MX25U51245G[];

extern const uint32_t SFDP_HEADER_MX25U51245G[];
extern const size_t SFDP_HEADER_MX25U51245G_LEN;

extern const uint32_t SFDP_PARAMS_ADDR_MX25U51245G;

extern const uint32_t SFDP_PARAMS_MX25U51245G[];
extern const size_t SFDP_PARAMS_MX25U51245G_LEN;

/* MX66UW2G345G */
extern const uint8_t FLASH_ID_MX66UW2G345G[];

extern const uint32_t SFDP_HEADER_MX66UW2G345G[];
extern const size_t SFDP_HEADER_MX66UW2G345G_LEN;

extern const uint32_t SFDP_PARAMS_ADDR_MX66UW2G345G;

extern const uint32_t SFDP_PARAMS_MX66UW2G345G[];
extern const size_t SFDP_PARAMS_MX66UW2G345G_LEN;


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

/* W25Q512JV */
extern const uint8_t FLASH_ID_W25Q512JV[];

extern const uint32_t SFDP_HEADER_W25Q512JV[];
extern const size_t SFDP_HEADER_W25Q512JV_LEN;

extern const uint32_t SFDP_PARAMS_ADDR_W25Q512JV;

extern const uint32_t SFDP_PARAMS_W25Q512JV[];
extern const size_t SFDP_PARAMS_W25Q512JV_LEN;


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

/* Infineon flash */

/* S28HS02GT */
extern const uint8_t FLASH_ID_S28HS02GT[];

extern const uint32_t SFDP_HEADER_S28HS02GT[];
extern const size_t SFDP_HEADER_S28HS02GT_LEN;

extern const uint32_t SFDP_PARAMS_ADDR_S28HS02GT;

extern const uint32_t SFDP_PARAMS_S28HS02GT[];
extern const size_t SFDP_PARAMS_S28HS02GT_LEN;


#endif	/* SPI_FLASH_SFDP_TESTING_H_ */
