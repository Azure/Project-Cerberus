// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCD_FLASH_H_
#define PCD_FLASH_H_

#include <stdint.h>
#include "pcd.h"
#include "platform_config.h"
#include "flash/flash.h"
#include "manifest/manifest_flash.h"


/* Configurable default PCD timeout and retry values.
 * Defaults can be overridden in platform_config.h. */
#ifndef PCD_FLASH_ATTESTATION_SUCCESS_RETRY_DEFAULT
#define PCD_FLASH_ATTESTATION_SUCCESS_RETRY_DEFAULT						86400000
#endif
#ifndef PCD_FLASH_ATTESTATION_FAIL_RETRY_DEFAULT
#define PCD_FLASH_ATTESTATION_FAIL_RETRY_DEFAULT						10000
#endif
#ifndef PCD_FLASH_DISCOVERY_FAIL_RETRY_DEFAULT
#define PCD_FLASH_DISCOVERY_FAIL_RETRY_DEFAULT							10000
#endif
#ifndef PCD_FLASH_MCTP_CTRL_TIMEOUT_DEFAULT
#define PCD_FLASH_MCTP_CTRL_TIMEOUT_DEFAULT								2000
#endif
#ifndef PCD_FLASH_MCTP_BRIDGE_GET_TABLE_WAIT_DEFAULT
#define PCD_FLASH_MCTP_BRIDGE_GET_TABLE_WAIT_DEFAULT					3000
#endif
#ifndef PCD_FLASH_MCTP_BRIDGE_ADDITIONAL_TIMEOUT_DEFAULT
#define PCD_FLASH_MCTP_BRIDGE_ADDITIONAL_TIMEOUT_DEFAULT				0
#endif
#ifndef PCD_FLASH_ATTESTATION_RSP_NOT_READY_MAX_DURATION_DEFAULT
#define PCD_FLASH_ATTESTATION_RSP_NOT_READY_MAX_DURATION_DEFAULT		1000
#endif
#ifndef PCD_FLASH_ATTESTATION_RSP_NOT_READY_MAX_RETRY_DEFAULT
#define PCD_FLASH_ATTESTATION_RSP_NOT_READY_MAX_RETRY_DEFAULT			3
#endif	/* PCD_FLASH_H_ */


/**
 * Defines a PCD that is stored in flash memory.
 */
struct pcd_flash {
	struct pcd base;					/**< The base PCD instance. */
	struct manifest_flash base_flash;	/**< The base PCD flash instance. */
};


int pcd_flash_init (struct pcd_flash *pcd, const struct flash *flash,
	const struct hash_engine *hash, uint32_t base_addr, uint8_t *signature_cache,
	size_t max_signature, uint8_t *platform_id_cache, size_t max_platform_id);
void pcd_flash_release (struct pcd_flash *pcd);


#endif	//PCD_FLASH_H
