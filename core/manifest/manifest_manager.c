// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "manifest_manager.h"
#include "platform.h"


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
int manifest_manager_get_port (struct manifest_manager *manager)
{
	if (manager) {
		return manager->port;
	}
	else {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}
}

/**
 * Get the data used for manifest ID measurement.
 *
 * @param active The manifest to query
 * @param offset The offset to read data from
 * @param buffer The output buffer to be filled with measured data
 * @param length Maximum length of the buffer
 *
 *@return length of the measured data if successfully retrieved or an error code.
 */
int manifest_manager_get_id_measured_data (struct manifest *active, size_t offset,
	uint8_t *buffer, size_t length)
{
	uint8_t id[5] = {0};
	size_t id_length = sizeof (id);
	size_t bytes_read;
	int status;

	if (buffer == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	if (offset > (id_length - 1)) {
		return 0;
	}

	if (active) {
		id[0] = 1;
		status = active->get_id (active, (uint32_t*) &id[1]);
		if (status != 0) {
			return status;
		}
	}

	bytes_read = ((id_length - offset) > length) ? length : (id_length - offset);

	memcpy (buffer, id + offset, bytes_read);

	return bytes_read;
}

/**
 * Get the data used for manifest platform ID measurement.
 *
 * @param active The manifest to query
 * @param offset The offset to read data from
 * @param buffer The output buffer to be filled with measured data
 * @param length Maximum length of the buffer
 *
 *@return length of the measured data if successfully retrieved or an error code.
 */
int manifest_manager_get_platform_id_measured_data (struct manifest *active, size_t offset,
	uint8_t *buffer, size_t length)
{
	char *id;
	size_t id_length;
	size_t bytes_read;
	char empty_string = '\0';
	int status;

	if (buffer == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	if (active) {
		status = active->get_platform_id (active, &id);
		if (status != 0) {
			return status;
		}

		id_length = strlen (id) + 1;
	}
	else {
		id = &empty_string;
		id_length = 1;
	}

	if (offset >= id_length) {
		bytes_read = 0;
		goto exit;
	}

	bytes_read = ((id_length - offset) > length) ? length : (id_length - offset);
	memcpy (buffer, id + offset, bytes_read);

exit:
	if (active) {
		platform_free (id);
	}
	return bytes_read;
}
