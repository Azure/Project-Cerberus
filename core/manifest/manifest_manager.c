// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "manifest_manager.h"
#include "platform_api.h"
#include "common/buffer_util.h"
#include "common/common_math.h"


/**
 * Initialize the manifest manager.
 *
 * @param manager The manager to initialize.
 * @param hash The hash engine to generate measurement data.
 *
 * @return 0 if the manifest manager was initialized successfully or an error code.
 */
int manifest_manager_init (struct manifest_manager *manager, const struct hash_engine *hash)
{
	if ((manager == NULL) || (hash == NULL)) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	manager->port = 0;
	manager->hash = hash;

	return 0;
}

/**
 * Set the port identifier for a manifest manager.
 *
 * @param host The manifest manager to configure.
 * @param port The port identifier to set.
 */
void manifest_manager_set_port (struct manifest_manager *manager, int port)
{
	if (manager) {
		manager->port = port;
	}
}

/**
 * Get the port identifier for a manifest manager.
 *
 * @param host The manifest manager instance to query.
 *
 * @return The port identifier or an error code.  Use ROT_IS_ERROR to check for errors.
 */
int manifest_manager_get_port (const struct manifest_manager *manager)
{
	if (manager) {
		if (manager->port < 0) {
			return 0;
		}
		else {
			return manager->port;
		}
	}
	else {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}
}

/**
 * Get the data used for the manifest digest measurement.
 *
 * @param active The manifest to query
 * @param hash Hash engine to use for manifest digest calculation.
 * @param offset The offset to read data from.
 * @param buffer The output buffer to be filled with measured data.
 * @param length Maximum length of the buffer.
 * @param total_len Output buffer with total length of measured data.  This will contain the total
 * length of the measurement even if only partially returned.
 *
 * @return Length of the measured data if successfully retrieved or an error code.
 */
int manifest_manager_get_manifest_digest_measured_data (const struct manifest *active,
	const struct hash_engine *hash, size_t offset, uint8_t *buffer, size_t length,
	uint32_t *total_len)
{
	uint8_t hash_out[SHA512_HASH_LENGTH] = {0};
	int hash_length = SHA256_HASH_LENGTH;

	if ((hash == NULL) || (buffer == NULL) || (total_len == NULL)) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	if (active) {
		hash_length = active->get_hash (active, hash, hash_out, sizeof (hash_out));
		if (ROT_IS_ERROR (hash_length)) {
			return hash_length;
		}
	}

	*total_len = hash_length;

	return buffer_copy (hash_out, hash_length, &offset, &length, buffer);
}

/**
 * Update a hash context with the data used for the manifest digest measurement.
 *
 * The two hash engines must be different instances.
 *
 * @param active The manifest to query.
 * @param manifest_hash Hash engine to use for manifest digest calculation.
 * @param measure_hash Hash engine to update with the measured data.
 *
 * @return 0 if the hash was updated successfully or an error code.
 */
int manifest_manager_hash_manifest_digest_measured_data (const struct manifest *active,
	const struct hash_engine *manifest_hash, const struct hash_engine *measure_hash)
{
	uint8_t hash_out[SHA512_HASH_LENGTH] = {0};
	int hash_length = SHA256_HASH_LENGTH;

	if ((manifest_hash == NULL) || (measure_hash == NULL)) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	if (manifest_hash == measure_hash) {
		return MANIFEST_MANAGER_SAME_HASH_ENGINE;
	}

	if (active) {
		hash_length = active->get_hash (active, manifest_hash, hash_out, sizeof (hash_out));
		if (ROT_IS_ERROR (hash_length)) {
			return hash_length;
		}
	}

	return measure_hash->update (measure_hash, hash_out, hash_length);
}

/**
 * Generate the data for the manifest ID measurement.
 *
 * @param active The manifest to query.
 * @param id Output for the ID.  This must be 5 bytes long.
 *
 * @return 0 if the ID was retrieved successfully or an error code.
 */
static int manifest_manager_construct_id_measurement_data (const struct manifest *active,
	uint8_t *id)
{
	int status;

	if (active) {
		id[0] = 1;
		status = active->get_id (active, (uint32_t*) &id[1]);
		if (status != 0) {
			return status;
		}
	}
	else {
		memset (id, 0, 5);
	}

	return 0;
}

/**
 * Get the data used for the manifest ID measurement.
 *
 * @param active The manifest to query.
 * @param offset The offset to read data from.
 * @param buffer The output buffer to be filled with measured data.
 * @param length Maximum length of the buffer.
 * @param total_len Output buffer with total length of manifest ID measurement. This should
 * 	contain total length of the measurement even if only partially returned.
 *
 * @return Length of the measured data if successfully retrieved or an error code.
 */
int manifest_manager_get_id_measured_data (const struct manifest *active, size_t offset,
	uint8_t *buffer, size_t length, uint32_t *total_len)
{
	uint8_t id[5];
	size_t id_length = sizeof (id);
	int status;

	if ((buffer == NULL) || (total_len == NULL)) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	*total_len = id_length;

	status = manifest_manager_construct_id_measurement_data (active, id);
	if (status != 0) {
		return status;
	}

	return buffer_copy (id, id_length, &offset, &length, buffer);
}

/**
 * Update a hash context with the data used for the manifest ID measurement.
 *
 * @param active The manifest to query.
 * @param hash Hash engine to update.
 *
 * @return 0 if the hash was updated successfully or an error code.
 */
int manifest_manager_hash_id_measured_data (const struct manifest *active,
	const struct hash_engine *hash)
{
	uint8_t id[5];
	int status;

	if (hash == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	status = manifest_manager_construct_id_measurement_data (active, id);
	if (status != 0) {
		return status;
	}

	return hash->update (hash, id, sizeof (id));
}

/**
 * Get the data used for the manifest platform ID measurement.
 *
 * @param active The manifest to query
 * @param offset The offset to read data from
 * @param buffer The output buffer to be filled with measured data
 * @param length Maximum length of the buffer
 * @param total_len Output buffer with total length of platform ID measurement. This should
 * 	contain total length of the measurement even if only partially returned.
 *
 * @return Length of the measured data if successfully retrieved or an error code.
 */
int manifest_manager_get_platform_id_measured_data (const struct manifest *active, size_t offset,
	uint8_t *buffer, size_t length, uint32_t *total_len)
{
	char *id = NULL;
	size_t id_length;
	size_t bytes_read;
	char empty_string = '\0';
	int status;

	if ((buffer == NULL) || (total_len == NULL)) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	if (active) {
		status = active->get_platform_id (active, &id, 0);
		if (status != 0) {
			return status;
		}

		id_length = strlen (id) + 1;
	}
	else {
		id = &empty_string;
		id_length = 1;
	}

	*total_len = id_length;

	bytes_read = buffer_copy ((uint8_t*) id, id_length, &offset, &length, buffer);

	if (active) {
		active->free_platform_id (active, id);
	}

	return bytes_read;
}

/**
 * Update a hash context with the data used for the manifest platform ID measurement.
 *
 * @param active The manifest to query.
 * @param hash Hash engine to update.
 *
 * @return 0 if the hash was updated successfully or an error code.
 */
int manifest_manager_hash_platform_id_measured_data (const struct manifest *active,
	const struct hash_engine *hash)
{
	char *id = NULL;
	char empty_string = '\0';
	int status;

	if (hash == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	if (active) {
		status = active->get_platform_id (active, &id, 0);
		if (status != 0) {
			return status;
		}
	}
	else {
		id = &empty_string;
	}

	status = hash->update (hash, (uint8_t*) id, strlen (id) + 1);

	if (active) {
		active->free_platform_id (active, id);
	}

	return status;
}

/**
 * Get the data used for the manifest measurement.
 *
 * This is functionally the same as manifest_manager_get_manifest_digest_measured_data but uses a
 * manifest_manager instance for the necessary hash engine.
 *
 * @param manager The manifest manager instance to query.
 * @param active The manifest to query
 * @param offset The offset to read data from
 * @param buffer The output buffer to be filled with measured data
 * @param length Maximum length of the buffer
 * @param total_len Output buffer with total length of measured data. This should contain total
 * 	length of the measurement even if only partially returned.
 *
 * @return Length of the measured data if successfully retrieved or an error code.
 */
int manifest_manager_get_manifest_measured_data (const struct manifest_manager *manager,
	const struct manifest *active, size_t offset, uint8_t *buffer, size_t length,
	uint32_t *total_len)
{
	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return manifest_manager_get_manifest_digest_measured_data (active, manager->hash, offset,
		buffer, length, total_len);
}

/**
 * Update a hash context with the data used for the manifest measurement.
 *
 * This is functionally the same as manifest_manager_hash_manifest_digest_measured_data but uses a
 * manifest_manager instance for the necessary hash engine.
 *
 * NOTE:  The hash context contained in the manifest manager must be different from the one passed
 * into this function as an argument.
 *
 * @param manager The manifest manager instance to query.
 * @param active The manifest to query.
 * @param hash Hash engine to update.  This must be different from the hash engined contained in the
 * manifest manager.
 *
 * @return 0 if the hash was updated successfully or an error code.
 */
int manifest_manager_hash_manifest_measured_data (const struct manifest_manager *manager,
	const struct manifest *active, const struct hash_engine *hash)
{
	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return manifest_manager_hash_manifest_digest_measured_data (active, manager->hash, hash);
}
