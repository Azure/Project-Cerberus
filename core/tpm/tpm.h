// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef TPM_H_
#define TPM_H_

#include <stdbool.h>
#include <stdint.h>
#include "flash/flash_store.h"
#include "host_fw/host_processor_observer.h"
#include "status/rot_status.h"


#define TPM_STORAGE_SEGMENT_SIZE					512

/**
 * Flash storage for TPM data.
 */
struct tpm {
	struct host_processor_observer observer;	/**< The base observer interface. */
	const struct flash_store *flash;			/**< The flash used for TPM storage. */
	uint16_t segment_storage_size;				/**< Size of TPM storage segment */
	uint8_t *buffer;							/**< Buffer for TPM storage segment */
};

#define TPM_MAGIC									0xACFE
#define	TPM_HEADER_FORMAT							0

/**
 * TPM header stored at the beginning of TPM NV storage.
 */
#pragma pack(push, 1)
struct tpm_header {
	uint16_t magic;			/**< Value indicating header is valid. */
	uint16_t format_id;		/**< Header format ID. */
	uint64_t nv_counter;	/**< Non-volatile counter. */
	uint8_t clear;			/**< Flag indicating a pending TPM clear. */
};

#pragma pack(pop)


int tpm_init (struct tpm *tpm, const struct flash_store *flash, uint8_t *segment_storage,
	int segment_storage_size);
int tpm_init_state (struct tpm *tpm);

void tpm_release (struct tpm *tpm);

int tpm_increment_counter (struct tpm *tpm);
int tpm_get_counter (struct tpm *tpm, uint64_t *counter);

int tpm_set_storage (struct tpm *tpm, uint8_t index, uint8_t *storage, size_t storage_len);
int tpm_get_storage (struct tpm *tpm, uint8_t index, uint8_t *storage, size_t storage_len,
	bool mask_data_error);

int tpm_schedule_clear (struct tpm *tpm);

int tpm_get_segment_storage_size (struct tpm *tpm, uint16_t *size);

#define	TPM_ERROR(code)		ROT_ERROR (ROT_MODULE_TPM, code)

/**
 * Error codes that can be generated by TPM.
 */
enum {
	TPM_INVALID_ARGUMENT = TPM_ERROR (0x00),		/**< Input parameter is null or not valid. */
	TPM_NO_MEMORY = TPM_ERROR (0x01),				/**< Memory allocation failed. */
	TPM_STORAGE_WRITE_FAIL = TPM_ERROR (0x02),		/**< Failure when writing to persistent storage. */
	TPM_INVALID_STORAGE = TPM_ERROR (0x03),			/**< TPM storage contents invalid. */
	TPM_INVALID_LEN = TPM_ERROR (0x04),				/**< Buffer provided too small for requested contents. */
	TPM_OUT_OF_RANGE = TPM_ERROR (0x05),			/**< Parameter out of range. */
	TPM_INVALID_SEGMENT = TPM_ERROR (0x06),			/**< TPM storage segment not written to. */
	TPM_STORAGE_NOT_ALIGNED = TPM_ERROR (0x07),		/**< Address for the TPM is not aligned correctly. */
	TPM_INSUFFICIENT_STORAGE = TPM_ERROR (0x08),	/**< There is not enough storage space for the TPM. */
	TPM_INCOMPLETE_WRITE = TPM_ERROR (0x09),		/**< Write to storage only partially completed. */
};


#endif	/* TPM_H_ */
