// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_LOADER_H_
#define FIRMWARE_LOADER_H_

#include <stdint.h>
#include <stddef.h>
#include "status/rot_status.h"
#include "crypto/hash.h"
#include "flash/flash.h"


/**
 * Interface to load a firmware image into processor memory for execution.
 */
struct firmware_loader {
	/**
	 * Determine if the target location for an image is valid.
	 *
	 * @param loader The firmware load handler to query.
	 * @param phy_addr The starting address where the firmware image would be loaded.  This should
	 * be a physical address.
	 * @param length Length of the image to load.
	 *
	 * @return 0 if the address is valid or an error code.
	 */
	int (*is_address_valid) (const struct firmware_loader *loader, uint64_t phy_addr,
		size_t length);

	/**
	 * Provide a virtual address mapping for a region of physical memory.
	 *
	 * Virtual addresses must be freed with firmware_loader.unmap_address.
	 *
	 * @param loader The firmware load handler to use for address mapping.
	 * @param phy_addr The physical address to map.
	 * @param length The minimum amount of memory that should be mapped.  It is acceptable for an
	 * implementation create a mapping to a larger region of memory.
	 * @param virt_addr Output for the virtual address to use for memory accesses.
	 *
	 * @return 0 if the physical memory was successfully mapped or an error code.
	 */
	int (*map_address) (const struct firmware_loader *loader, uint64_t phy_addr, size_t length,
		void **virt_addr);

	/**
	 * Release a virtual address mapping.
	 *
	 * @param loader The firmware load handler that provided the address mapping.
	 * @param virt_addr The virtual address to unmap.
	 */
	void (*unmap_address) (const struct firmware_loader *loader, void *virt_addr);

	/**
	 * Load an image from flash into processor memory.
	 *
	 * A digest will be calculated for the data that was loaded, if requested.  If the image is
	 * encrypted, it will be decrypted before calculating the digest.
	 *
	 * @param loader The firmware load handler to execute.
	 * @param flash Flash where the firmware image should be loaded from.
	 * @param src_addr Address on flash where the image is stored.
	 * @param length Total length of the image to load.
	 * @param dest_addr Address in memory where the image will be loaded to.
	 * @param iv The IV to use for decrypting an encrypted image.  If the image is not encrypted,
	 * this should be null.
	 * @param iv_length Length of the IV data.  This will be ignored if the IV is null.
	 * @param hash Hash engine to use for generating the image digest.  If no image hash is
	 * required, this should be null.
	 * @param hash_algo The algorithm to use for generating the image digest.  This will be ignored
	 * if no hash engine has been provided.
	 * @param digest Output buffer for the image digest.  This will be ignored if no hash engine has
	 * been provided.
	 * @param digest_length Length of the digest buffer.  This will be ignored if no hash engine has
	 * been provided.
	 *
	 * @return 0 if the image was loaded into memory successfully or an error code.
	 */
	int (*load_image) (const struct firmware_loader *loader, const struct flash *flash,
		uint32_t src_addr, size_t length, uint8_t *dest_addr, const uint8_t *iv, size_t iv_length,
		struct hash_engine *hash, enum hash_type hash_algo, uint8_t *digest, size_t digest_length);

	/**
	 * Load an image from flash into processor memory.
	 *
	 * An existing digest will be updated to include the data that was loaded.  If the image is
	 * encrypted, it will be decrypted before the digest is updated.
	 *
	 * @param loader The firmware load handler to execute.
	 * @param flash Flash where the firmware image should be loaded from.
	 * @param src_addr Address on flash where the image is stored.
	 * @param length Total length of the image to load.
	 * @param dest_addr Address in memory where the image will be loaded to.
	 * @param iv The IV to use for decrypting an encrypted image.  If the image is not encrypted,
	 * this should be null.
	 * @param iv_length Length of the IV data.  This will be ignored if the IV is null.
	 * @param hash Hash engine to use for updating the image digest.  It is up to the caller to
	 * start an finish the digest calculation.
	 *
	 * @return 0 if the image was loaded into memory successfully or an error code.
	 */
	int (*load_image_update_digest) (const struct firmware_loader *loader,
		const struct flash *flash, uint32_t src_addr, size_t length, uint8_t *dest_addr,
		const uint8_t *iv, size_t iv_length, struct hash_engine *hash);

	/**
	 * Copy an image resident in directly accessible memory to the target location for execution.
	 * It is allowed for the source and target memory locations to overlap.
	 *
	 * A digest will be calculated for the date that was loaded, if requested.  If the image is
	 * encrypted, it will be decrypted before calculating the digest.
	 *
	 * @param loader The firmware load handler to execute.
	 * @param src_addr Memory address where the image is located.
	 * @param length Total length of the image to copy.
	 * @param dest_addr Address in memory where the image will be loaded to.
	 * @param iv The IV to use for decrypting an encrypted image.  If the image is not encrypted,
	 * this should be null.
	 * @param iv_length Length of the IV data.  This will be ignored if the IV is null.
	 * @param hash Hash engine to use for generating the image digest.  If no image hash is
	 * required, this should be null.
	 * @param hash_algo The algorithm to use for generating the image digest.  This will be ignored
	 * if no hash engine has been provided.
	 * @param digest Output buffer for the image digest.  This will be ignored if no hash engine has
	 * been provided.
	 * @param digest_length Length of the digest buffer.  This will be ignored if no hash engine has
	 * been provided.
	 *
	 * @return 0 if the image was successfully copied to the target memory or an error code.
	 */
	int (*copy_image) (const struct firmware_loader *loader, const uint8_t *src_addr, size_t length,
		uint8_t *dest_addr, const uint8_t *iv, size_t iv_length, struct hash_engine *hash,
		enum hash_type hash_algo, uint8_t *digest, size_t digest_length);

	/**
	 * Copy an image resident in directly accessible memory to the target location for execution.
	 * It is allowed for the source and target memory locations to overlap.
	 *
	 * An existing digest will be updated to include the data that was loaded.  If the image is
	 * encrypted, it will be decrypted before the digest is updated.
	 *
	 * @param loader The firmware load handler to execute.
	 * @param src_addr Memory address where the image is located.
	 * @param length Total length of the image to copy.
	 * @param dest_addr Address in memory where the image will be loaded to.
	 * @param iv The IV to use for decrypting an encrypted image.  If the image is not encrypted,
	 * this should be null.
	 * @param iv_length Length of the IV data.  This will be ignored if the IV is null.
	 * @param hash Hash engine to use for updating the image digest.  It is up to the caller to
	 * start an finish the digest calculation.
	 *
	 * @return 0 if the image was successfully copied to the target memory or an error code.
	 */
	int (*copy_image_update_digest) (const struct firmware_loader *loader, const uint8_t *src_addr,
		size_t length, uint8_t *dest_addr, const uint8_t *iv, size_t iv_length,
		struct hash_engine *hash);
};


#define	FIRMWARE_LOADER_ERROR(code)		ROT_ERROR (ROT_MODULE_FIRMWARE_LOADER, code)

/**
 * Error codes that can be generated by a handler for loading firmware images.
 */
enum {
	FIRMWARE_LOADER_INVALID_ARGUMENT = FIRMWARE_LOADER_ERROR (0x00),			/**< Input parameter is null or not valid. */
	FIRMWARE_LOADER_NO_MEMORY = FIRMWARE_LOADER_ERROR (0x01),					/**< Memory allocation failed. */
	FIRMWARE_LOADER_ADDR_CHECK_FAILED = FIRMWARE_LOADER_ERROR (0x02),			/**< Failed to determine if a target address is valid. */
	FIRMWARE_LOADER_LOAD_IMG_FAILED = FIRMWARE_LOADER_ERROR (0x03),				/**< Failed to load an image into memory. */
	FIRMWARE_LOADER_INVALID_ADDR = FIRMWARE_LOADER_ERROR (0x04),				/**< The target address for loading an image is not valid. */
	FIRMWARE_LOADER_IMAGE_TOO_LARGE = FIRMWARE_LOADER_ERROR (0x05),				/**< The image will not fit in the target memory. */
	FIRMWARE_LOADER_BAD_IV_LENGTH = FIRMWARE_LOADER_ERROR (0x06),				/**< The IV length is not correct for the image. */
	FIRMWARE_LOADER_ENCRYPTION_NOT_SUPPORTED = FIRMWARE_LOADER_ERROR (0x07),	/**< Encrypted images are not supported. */
	FIRMWARE_LOADER_COPY_IMG_FAILED = FIRMWARE_LOADER_ERROR (0x08),				/**< Failed to copy on image from memory. */
	FIRMWARE_LOADER_MAP_ADDR_FAILED = FIRMWARE_LOADER_ERROR (0x09),				/**< Failed to allocate a virtual address. */
};


#endif /* FIRMWARE_LOADER_H_ */
