// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"
#include "common/buffer_util.h"
#include "common/common_math.h"
#include "flash/flash_util.h"
#include "manifest/manifest_flash.h"
#include "cfm_format.h"
#include "cfm_flash.h"


static int cfm_flash_verify (struct manifest *cfm, struct hash_engine *hash,
	struct signature_verification *verification, uint8_t *hash_out, size_t hash_length)
{
	struct cfm_flash *cfm_flash = (struct cfm_flash*) cfm;

	if (cfm_flash == NULL) {
		return CFM_INVALID_ARGUMENT;
	}

	return manifest_flash_verify (&cfm_flash->base_flash, hash, verification, hash_out,
		hash_length);
}

static int cfm_flash_get_id (struct manifest *cfm, uint32_t *id)
{
	struct cfm_flash *cfm_flash = (struct cfm_flash*) cfm;

	if (cfm_flash == NULL) {
		return CFM_INVALID_ARGUMENT;
	}

	return manifest_flash_get_id (&cfm_flash->base_flash, id);
}

static int cfm_flash_get_platform_id (struct manifest *cfm, char **id, size_t length)
{
	struct cfm_flash *cfm_flash = (struct cfm_flash*) cfm;

	if (cfm_flash == NULL) {
		return CFM_INVALID_ARGUMENT;
	}

	return manifest_flash_get_platform_id (&cfm_flash->base_flash, id, length);
}

static void cfm_flash_free_platform_id (struct manifest *manifest, char *id)
{
	/* Don't need to do anything.  Manifest allocated buffers use the internal static buffer. */
}

static int cfm_flash_get_hash (struct manifest *cfm, struct hash_engine *hash, uint8_t *hash_out,
	size_t hash_length)
{
	struct cfm_flash *cfm_flash = (struct cfm_flash*) cfm;

	if (cfm_flash == NULL) {
		return CFM_INVALID_ARGUMENT;
	}

	return manifest_flash_get_hash (&cfm_flash->base_flash, hash, hash_out, hash_length);
}

static int cfm_flash_get_signature (struct manifest *cfm, uint8_t *signature, size_t length)
{
	struct cfm_flash *cfm_flash = (struct cfm_flash*) cfm;

	if (cfm_flash == NULL) {
		return CFM_INVALID_ARGUMENT;
	}

	return manifest_flash_get_signature (&cfm_flash->base_flash, signature, length);
}

static int cfm_flash_is_empty (struct manifest *cfm)
{
	struct cfm_flash *cfm_flash = (struct cfm_flash*) cfm;

	if (cfm_flash == NULL) {
		return CFM_INVALID_ARGUMENT;
	}

	if (!cfm_flash->base_flash.manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	/* Every CFM must have a platform ID.  If that is all we have, then it is an empty manifest. */
	return (cfm_flash->base_flash.toc_header.entry_count == 1);
}

/**
 * Find component device element for the specified component type.
 *
 * @param cfm The CFM to query.
 * @param component_type The component type to find.
 * @param component Output for the component device data.
 * @param entry Optional input for starting entry to use, then output for the entry index
 * 	following the matching component device element if found.  This can be null if not needed.
 *
 * @return 0 if the component device element was found or an error code.
 */
static int cfm_flash_get_component_device_with_starting_entry (struct cfm *cfm,
	const char *component_type, struct cfm_component_device_element *component, uint8_t *entry)
{
	struct cfm_flash *cfm_flash = (struct cfm_flash*) cfm;
	uint8_t element_entry = 0;
	int status;

	if ((cfm == NULL) || (component_type == NULL) || (component == NULL)) {
		return CFM_INVALID_ARGUMENT;
	}

	if (entry != NULL) {
		element_entry = *entry;
	}

	do {
		status = manifest_flash_read_element_data (&cfm_flash->base_flash,
			cfm_flash->base_flash.hash, CFM_COMPONENT_DEVICE, element_entry, MANIFEST_NO_PARENT, 0,
			&element_entry, NULL, NULL, (uint8_t**) &component,
			sizeof (struct cfm_component_device_element));
		if (ROT_IS_ERROR (status)) {
			return status;
		}

		element_entry++;
		component->type[component->type_len] = '\0';
	} while (strcmp (component_type, (char*) component->type) != 0);

	if (entry != NULL) {
		*entry = element_entry;
	}

	return 0;
}

static void cfm_flash_free_component_device (struct cfm *cfm,
	struct cfm_component_device *component)
{
	if (component != NULL) {
		platform_free ((void*) component->type);
		platform_free ((void*) component->pmr_id_list);
	}
}

static int cfm_flash_get_pmr_id_list (struct cfm *cfm, uint8_t entry, uint8_t **pmr_list)
{
	struct cfm_flash *cfm_flash = (struct cfm_flash*) cfm;
	struct cfm_pmr_digest_element pmr_digest_element;
	struct cfm_pmr_digest_element *pmr_digest_element_ptr = &pmr_digest_element;
	int num_pmr_digest;
	int i_pmr_digest;
	int status;

	num_pmr_digest = manifest_flash_get_num_child_elements (&cfm_flash->base_flash,
		cfm_flash->base_flash.hash, entry, CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT,
		CFM_PMR_DIGEST, NULL);
	if (ROT_IS_ERROR (num_pmr_digest)) {
		return num_pmr_digest;
	}

	*pmr_list = platform_malloc (sizeof (uint8_t) * num_pmr_digest);
	if (*pmr_list == NULL) {
		return CFM_NO_MEMORY;
	}

	for (i_pmr_digest = 0; i_pmr_digest < num_pmr_digest; ++i_pmr_digest) {
		status = manifest_flash_read_element_data (&cfm_flash->base_flash,
			cfm_flash->base_flash.hash,	CFM_PMR_DIGEST, entry, CFM_COMPONENT_DEVICE, 0, &entry,
			NULL, NULL, (uint8_t**) &pmr_digest_element_ptr,
			sizeof (struct cfm_pmr_digest_element));
		if (ROT_IS_ERROR (status)) {
			if (status == MANIFEST_CHILD_NOT_FOUND) {
				status = CFM_ELEMENT_NOT_FOUND;
			}

			goto fail;
		}

		(*pmr_list)[i_pmr_digest] = pmr_digest_element.pmr_id;

		++entry;
	}

	return num_pmr_digest;

fail:
	platform_free (*pmr_list);
	*pmr_list = NULL;

	return status;
}

static int cfm_flash_get_component_device (struct cfm *cfm, const char *component_type,
	struct cfm_component_device *component)
{
	struct cfm_component_device_element component_element;
	uint8_t entry = 0;
	int status;

	if (component == NULL) {
		return CFM_INVALID_ARGUMENT;
	}

	status = cfm_flash_get_component_device_with_starting_entry (cfm, component_type,
		&component_element, &entry);
	if (status == 0) {
		component->attestation_protocol = component_element.attestation_protocol;
		component->cert_slot = component_element.cert_slot;

		component->type = strdup ((char*) component_element.type);
		if (component->type == NULL) {
			return CFM_NO_MEMORY;
		}

		status = cfm_flash_get_pmr_id_list (cfm, entry, (uint8_t**) &component->pmr_id_list);
		if (ROT_IS_ERROR (status)) {
			platform_free ((void*) component->type);
			return status;
		}

		component->num_pmr_digest = status;

		return 0;
	}

	return status;
}

static int cfm_flash_buffer_supported_components (struct cfm *cfm, size_t offset, size_t length,
	uint8_t *components)
{
	struct cfm_flash *cfm_flash = (struct cfm_flash*) cfm;
	struct cfm_component_device_element component;
	uint8_t *component_ptr;
	size_t i_components = 0;
	size_t remaining_len = length;
	size_t component_len;
	uint8_t entry = 0;
	int status;

	if ((cfm_flash == NULL) || (components == NULL) || (length == 0)) {
		return CFM_INVALID_ARGUMENT;
	}

	if (!cfm_flash->base_flash.manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	while (i_components < length) {
		component_ptr = (uint8_t*) &component;

		status = manifest_flash_read_element_data (&cfm_flash->base_flash,
			cfm_flash->base_flash.hash, CFM_COMPONENT_DEVICE, entry, MANIFEST_NO_PARENT, 0, &entry,
			NULL, &component_len, &component_ptr, sizeof (struct cfm_component_device_element));
		if (ROT_IS_ERROR (status)) {
			if ((status == MANIFEST_ELEMENT_NOT_FOUND) && (i_components != 0)) {
				goto done;
			}

			return status;
		}

		++entry;

		component.type[component.type_len] = '\0';
		i_components += buffer_copy (component.type, component.type_len + 1, &offset,
			&remaining_len, &components[i_components]);
	}

done:
	return i_components;
}

/**
 * Common function used to get next element data for the specified component and element type.
 *
 * @param cfm The CFM to query.
 * @param component_type The component type to find element for.
 * @param buffer A container to be updated with the pointer to requested element data.  If the
 *  buffer is null, a buffer will by dynamically allocated to fit the entire element.  This buffer
 *  must be freed by the caller.
 * @param buffer_len Length of the element output buffer incoming if the buffer is not null.  Buffer
 * 	will then be updated with length of buffer. If buffer is null, then optional and can be null if
 *  not needed.
 * @param entry Optional input for starting entry to use, then output for the entry index following
 * 	the matching element if found.  This can be null if not needed.
 * @param element_type Element type to retrieve.
 *
 * @return 0 if the element was found or an error code.
 */
static int cfm_flash_get_next_element (struct cfm *cfm, const char *component_type,
	uint8_t **buffer, size_t *buffer_len, uint8_t *entry, int element_type)
{
	struct cfm_flash *cfm_flash = (struct cfm_flash*) cfm;
	struct cfm_component_device_element component;
	uint8_t element_entry = 0;
	size_t *buffer_len_ptr = buffer_len;
	size_t buffer_len_buf;
	int num_element;
	int status;

	if ((cfm_flash == NULL) || (component_type == NULL) || (buffer == NULL) ||
		((*buffer != NULL) && (buffer_len == NULL))) {
		return CFM_INVALID_ARGUMENT;
	}

	if (!cfm_flash->base_flash.manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	if (entry != NULL) {
		element_entry = *entry;
	}

	if (element_entry == 0) {
		status = cfm_flash_get_component_device_with_starting_entry (cfm, component_type,
			&component, &element_entry);
		if (status != 0) {
			return status;
		}
	}

	if (buffer_len == NULL) {
		buffer_len_ptr = &buffer_len_buf;
	}

	num_element = manifest_flash_get_num_child_elements (&cfm_flash->base_flash,
		cfm_flash->base_flash.hash, element_entry, CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT,
		element_type, NULL);
	if (ROT_IS_ERROR (num_element)) {
		return num_element;
	}

	if (num_element == 0) {
		goto not_found;
	}

	status = manifest_flash_read_element_data (&cfm_flash->base_flash, cfm_flash->base_flash.hash,
		element_type, element_entry, CFM_COMPONENT_DEVICE, 0, &element_entry, NULL,	buffer_len_ptr,
		(uint8_t**) buffer, (buffer_len == NULL) ? 0 : *buffer_len);
	if (ROT_IS_ERROR (status)) {
		if (status == MANIFEST_CHILD_NOT_FOUND) {
			goto not_found;
		}

		return status;
	}

	if (entry != NULL) {
		*entry = element_entry + 1;
	}

	return 0;

not_found:
	return CFM_ELEMENT_NOT_FOUND;
}

static int cfm_flash_get_component_pmr (struct cfm *cfm, const char *component_type, uint8_t pmr_id,
	struct cfm_pmr *pmr)
{
	struct cfm_pmr_element pmr_element;
	struct cfm_pmr_element *pmr_element_ptr = &pmr_element;
	size_t pmr_element_len;
	uint8_t entry = 0;
	int hash_len;
	int status;

	if ((pmr == NULL) || (pmr == NULL)) {
		return CFM_INVALID_ARGUMENT;
	}

	while (1) {
		pmr_element_len = sizeof (struct cfm_pmr_element);

		status = cfm_flash_get_next_element (cfm, component_type, (uint8_t**) &pmr_element_ptr,
			&pmr_element_len, &entry, CFM_PMR);
		if (status != 0) {
			if (status == CFM_ELEMENT_NOT_FOUND) {
				return CFM_PMR_NOT_FOUND;
			}

			return status;
		}

		if (pmr_element.pmr_id == pmr_id) {
			hash_len = hash_get_hash_len (pmr_element.hash_type + 1);
			if (ROT_IS_ERROR (hash_len)) {
				return hash_len;
			}

			pmr->pmr_id = pmr_element.pmr_id;
			pmr->initial_value_len = hash_len;

			memcpy ((void*) pmr->initial_value, pmr_element.initial_value, hash_len);

			return 0;
		}
	}
}

/**
 * Common function used to free cfm_digests container.
 *
 * @param cfm The CFM to query.
 * @param digests The CFM digests container with content to free.
 */
static void cfm_flash_free_cfm_digests (struct cfm *cfm, struct cfm_digests *digests)
{
	platform_free ((void*) digests->digests);
}

/**
 * Common function used to read a list of digests from CFM entry and offset provided, then
 * generating a cfm_digests container with the output.
 *
 * @param cfm The CFM to query.
 * @param digests The cfm_digests container to fill up.
 * @param digest_count The number of digests to read.
 * @param hash_type The type of digests to read.
 * @param element_type The type of element digests list is part of.
 * @param entry The entry number of the element being read.
 * @param offset The offset into the element being read the digests list is at.
 *
 * @return 0 if the container was generated successfully or an error code.
 */
static int cfm_flash_populate_digests (struct cfm *cfm, struct cfm_digests *digests,
	size_t digest_count, enum hash_type hash_type, uint8_t element_type, int entry, uint32_t offset)
{
	struct cfm_flash *cfm_flash = (struct cfm_flash*) cfm;
	size_t digests_len;
	int hash_len;
	int status;

	hash_len = hash_get_hash_len (hash_type + 1);
	if (ROT_IS_ERROR (hash_len)) {
		return hash_len;
	}

	digests_len = hash_len * digest_count;

	digests->digests = platform_malloc (digests_len);
	if (digests->digests == NULL) {
		return CFM_NO_MEMORY;
	}

	digests->digest_count = digest_count;
	digests->hash_len = hash_len;

	status = manifest_flash_read_element_data (&cfm_flash->base_flash, cfm_flash->base_flash.hash,
		element_type, entry, CFM_COMPONENT_DEVICE, offset, NULL, NULL, NULL,
		(uint8_t**) &digests->digests, digests_len);
	if (ROT_IS_ERROR (status)) {
		if (status == MANIFEST_CHILD_NOT_FOUND) {
			status = CFM_ELEMENT_MISSING_DIGESTS;
		}

		cfm_flash_free_cfm_digests (cfm, digests);

		return status;
	}

	return 0;
}

static void cfm_flash_free_component_pmr_digest (struct cfm *cfm, struct cfm_pmr_digest *pmr_digest)
{
	if (pmr_digest != NULL) {
		cfm_flash_free_cfm_digests (cfm, &pmr_digest->digests);
	}
}

static int cfm_flash_get_component_pmr_digest (struct cfm *cfm, const char *component_type,
	uint8_t pmr_id, struct cfm_pmr_digest *pmr_digest)
{
	struct cfm_pmr_digest_element pmr_digest_element;
	struct cfm_pmr_digest_element *pmr_digest_element_ptr = &pmr_digest_element;
	size_t pmr_digest_element_len;
	uint8_t entry = 0;
	int status;

	if (pmr_digest == NULL) {
		return CFM_INVALID_ARGUMENT;
	}

	while (1) {
		pmr_digest_element_len = sizeof (struct cfm_pmr_digest_element);

		status = cfm_flash_get_next_element (cfm, component_type,
			(uint8_t**) &pmr_digest_element_ptr, &pmr_digest_element_len, &entry, CFM_PMR_DIGEST);
		if (status != 0) {
			if (status == CFM_ELEMENT_NOT_FOUND) {
				return CFM_PMR_DIGEST_NOT_FOUND;
			}

			return status;
		}

		if (pmr_digest_element.pmr_id == pmr_id) {
			pmr_digest->pmr_id = pmr_digest_element.pmr_id;

			return cfm_flash_populate_digests (cfm, &pmr_digest->digests,
				pmr_digest_element.digest_count, pmr_digest_element.pmr_hash_type, CFM_PMR_DIGEST,
				entry - 1, sizeof (struct cfm_pmr_digest_element));
		}
	}
}

static void cfm_flash_free_measurement (struct cfm *cfm, struct cfm_measurement *pmr_measurement)
{
	if (pmr_measurement != NULL) {
		cfm_flash_free_cfm_digests (cfm, &pmr_measurement->digests);
	}
}

static int cfm_flash_get_next_measurement (struct cfm *cfm, const char *component_type,
	struct cfm_measurement *pmr_measurement, bool first)
{
	struct cfm_measurement_element measurement_element;
	struct cfm_measurement_element *measurement_element_ptr = &measurement_element;
	size_t measurement_element_len = sizeof (struct cfm_measurement_element);
	uint8_t *element_entry_ptr;
	int status;

	if (pmr_measurement == NULL) {
		return CFM_INVALID_ARGUMENT;
	}

	element_entry_ptr = (uint8_t*) &pmr_measurement->context;

	if (first) {
		*element_entry_ptr = 0;
	}

	status = cfm_flash_get_next_element (cfm, component_type, (uint8_t**) &measurement_element_ptr,
		&measurement_element_len, element_entry_ptr, CFM_MEASUREMENT);
	if (status != 0) {
		if (status == CFM_ELEMENT_NOT_FOUND) {
			return CFM_MEASUREMENT_NOT_FOUND;
		}

		return status;
	}

	pmr_measurement->pmr_id = measurement_element.pmr_id;
	pmr_measurement->measurement_id = measurement_element.measurement_id;

	return cfm_flash_populate_digests (cfm, &pmr_measurement->digests,
		measurement_element.digest_count, measurement_element.hash_type, CFM_MEASUREMENT,
		*element_entry_ptr - 1, sizeof (struct cfm_measurement_element));
}

static void cfm_flash_free_measurement_data (struct cfm *cfm,
	struct cfm_measurement_data *measurement_data)
{
	uint8_t i_check;

	if (measurement_data != NULL) {
		for (i_check = 0; i_check < measurement_data->check_count; ++i_check) {
			platform_free ((void*) measurement_data->check[i_check].bitmask);
			platform_free ((void*) measurement_data->check[i_check].allowable_data);
		}

		platform_free (measurement_data->check);
	}
}

static int cfm_flash_get_next_measurement_data (struct cfm *cfm, const char *component_type,
	struct cfm_measurement_data *measurement_data, bool first)
{
	struct cfm_flash *cfm_flash = (struct cfm_flash*) cfm;
	struct cfm_measurement_data_element measurement_data_element;
	struct cfm_measurement_data_element *measurement_data_element_ptr = &measurement_data_element;
	struct cfm_allowable_data_element allowable_data_element;
	struct cfm_allowable_data_element *allowable_data_element_ptr = &allowable_data_element;
	struct cfm_allowable_data *allowable_data_ptr;
	size_t measurement_data_element_len = sizeof (struct cfm_measurement_data_element);
	size_t allowable_data_len;
	size_t offset;
	uint8_t i_allowable_data;
	uint8_t *element_entry_ptr;
	int num_allowable_data;
	int status;

	if (measurement_data == NULL) {
		return CFM_INVALID_ARGUMENT;
	}

	element_entry_ptr = (uint8_t*) &measurement_data->context;

	if (first) {
		*element_entry_ptr = 0;
	}

	measurement_data->check_count = 0;
	measurement_data->check = NULL;

	status = cfm_flash_get_next_element (cfm, component_type,
		(uint8_t**) &measurement_data_element_ptr, &measurement_data_element_len, element_entry_ptr,
		CFM_MEASUREMENT_DATA);
	if (ROT_IS_ERROR (status)) {
		if (status == CFM_ELEMENT_NOT_FOUND) {
			return CFM_MEASUREMENT_DATA_NOT_FOUND;
		}

		return status;
	}

	measurement_data->pmr_id = measurement_data_element.pmr_id;
	measurement_data->measurement_id = measurement_data_element.measurement_id;

	num_allowable_data = manifest_flash_get_num_child_elements (&cfm_flash->base_flash,
		cfm_flash->base_flash.hash, *element_entry_ptr, CFM_MEASUREMENT_DATA, CFM_COMPONENT_DEVICE,
		CFM_ALLOWABLE_DATA, NULL);
	if (ROT_IS_ERROR (num_allowable_data)) {
		return num_allowable_data;
	}

	measurement_data->check_count = num_allowable_data;
	measurement_data->check =
		platform_calloc (measurement_data->check_count, sizeof (struct cfm_allowable_data));
	if (measurement_data->check == NULL) {
		return CFM_NO_MEMORY;
	}

	for (i_allowable_data = 0; i_allowable_data < num_allowable_data; ++i_allowable_data) {
		status = manifest_flash_read_element_data (&cfm_flash->base_flash,
			cfm_flash->base_flash.hash,	CFM_ALLOWABLE_DATA, *element_entry_ptr,
			CFM_MEASUREMENT_DATA, 0, NULL, NULL, NULL, (uint8_t**) &allowable_data_element_ptr,
			sizeof (struct cfm_allowable_data_element));
		if (ROT_IS_ERROR (status)) {
			if (status == MANIFEST_CHILD_NOT_FOUND) {
				status = CFM_ELEMENT_NOT_FOUND;
			}

			goto free_allowable_data;
		}

		allowable_data_ptr = &measurement_data->check[i_allowable_data];
		allowable_data_ptr->check = allowable_data_element_ptr->check;
		allowable_data_ptr->data_len = allowable_data_element_ptr->data_len;
		allowable_data_ptr->data_count = allowable_data_element_ptr->num_data;

		offset = sizeof (struct cfm_allowable_data_element);

		if (allowable_data_element_ptr->bitmask_presence) {
			allowable_data_ptr->bitmask = platform_malloc (allowable_data_ptr->data_len);
			if (allowable_data_ptr->bitmask == NULL) {
				status = CFM_NO_MEMORY;
				goto free_allowable_data;
			}

			status = manifest_flash_read_element_data (&cfm_flash->base_flash,
				cfm_flash->base_flash.hash,	CFM_ALLOWABLE_DATA, *element_entry_ptr,
				CFM_MEASUREMENT_DATA, offset, NULL, NULL, NULL,
				(uint8_t**) &allowable_data_ptr->bitmask, allowable_data_ptr->data_len);
			if (ROT_IS_ERROR (status)) {
				goto free_allowable_data;
			}

			offset += (((size_t) allowable_data_ptr->data_len + 3) & ~((size_t) 3));
		}

		allowable_data_len = allowable_data_ptr->data_len * allowable_data_ptr->data_count;

		allowable_data_ptr->allowable_data = platform_malloc (allowable_data_len);
		if (allowable_data_ptr->allowable_data == NULL) {
			status = CFM_NO_MEMORY;
			goto free_allowable_data;
		}

		status = manifest_flash_read_element_data (&cfm_flash->base_flash,
			cfm_flash->base_flash.hash,	CFM_ALLOWABLE_DATA, *element_entry_ptr,
			CFM_MEASUREMENT_DATA, offset, element_entry_ptr, NULL, NULL,
			(uint8_t**) &allowable_data_ptr->allowable_data, allowable_data_len);
		if (ROT_IS_ERROR (status)) {
			goto free_allowable_data;
		}

		*element_entry_ptr = *element_entry_ptr + 1;
	}

	return 0;

free_allowable_data:
	cfm_flash_free_measurement_data (cfm, measurement_data);

	return status;
}

static void cfm_flash_free_root_ca_digest (struct cfm *cfm,
	struct cfm_root_ca_digests *root_ca_digest)
{
	if (root_ca_digest != NULL) {
		cfm_flash_free_cfm_digests (cfm, &root_ca_digest->digests);
	}
}

static int cfm_flash_get_root_ca_digest (struct cfm *cfm, const char *component_type,
	struct cfm_root_ca_digests *root_ca_digest)
{
	struct cfm_root_ca_digests_element root_ca_digests_element;
	struct cfm_root_ca_digests_element *root_ca_digests_element_ptr = &root_ca_digests_element;
	size_t root_ca_digests_element_len = sizeof (struct cfm_root_ca_digests_element);
	uint8_t entry = 0;
	int status;

	if (root_ca_digest == NULL) {
		return CFM_INVALID_ARGUMENT;
	}

	status = cfm_flash_get_next_element (cfm, component_type,
		(uint8_t**) &root_ca_digests_element_ptr, &root_ca_digests_element_len, &entry,
		CFM_ROOT_CA);
	if (status == CFM_ELEMENT_NOT_FOUND) {
		return CFM_ROOT_CA_NOT_FOUND;
	}
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	return cfm_flash_populate_digests (cfm, &root_ca_digest->digests,
		root_ca_digests_element.ca_count, root_ca_digests_element.hash_type, CFM_ROOT_CA, entry - 1,
		sizeof (struct cfm_root_ca_digests_element));
}

static void cfm_flash_free_manifest (struct cfm *cfm, struct cfm_manifest *manifest)
{
	uint8_t i_check;

	if (manifest != NULL) {
		for (i_check = 0; i_check < manifest->check_count; ++i_check) {
			platform_free ((void*) manifest->check[i_check].allowable_id);
		}

		platform_free (manifest->check);
		platform_free ((void*) manifest->platform_id);
	}
}

/**
 * Common function used to find next allowable manifest element for the specified component type.
 *
 * @param cfm The CFM to query.
 * @param component_type The component type to find allowable manifest for.
 * @param manifest_type The manifest type to find.
 * @param allowable_manifest A container to be updated with the component allowable manifest
 * 	information.  Contents of the container are dynamically allocated and need to be freed using
 * 	free_manifest.
 * @param first Fetch first allowable manifest from CFM, or next allowable manifest since last call.
 *
 * @return 0 if the allowable manifest element was found or an error code.
 */
int cfm_flash_get_next_manifest (struct cfm *cfm, const char *component_type, int manifest_type,
	struct cfm_manifest *allowable_manifest, bool first)
{
	struct cfm_flash *cfm_flash = (struct cfm_flash*) cfm;
	struct cfm_allowable_pfm_element allowable_pfm_element;
	struct cfm_allowable_pfm_element *allowable_pfm_element_ptr = &allowable_pfm_element;
	struct cfm_allowable_id_element allowable_id_element;
	struct cfm_allowable_id_element *allowable_id_element_ptr = &allowable_id_element;
	struct cfm_allowable_id *allowable_id_ptr;
	size_t allowable_pfm_element_len = sizeof (struct cfm_allowable_pfm_element);
	size_t ids_len;
	size_t offset;
	uint8_t *element_entry_ptr;
	int num_allowable_id;
	int i_allowable_id;
	int status;

	if (allowable_manifest == NULL) {
		return CFM_INVALID_ARGUMENT;
	}

	element_entry_ptr = (uint8_t*) &allowable_manifest->context;

	if (first) {
		*element_entry_ptr = 0;
	}

	allowable_manifest->check_count = 0;
	allowable_manifest->check = NULL;


	// All allowable manifest elements have the same format, so use allowable PFM element containers
	status = cfm_flash_get_next_element (cfm, component_type,
		(uint8_t**) &allowable_pfm_element_ptr, &allowable_pfm_element_len, element_entry_ptr,
		manifest_type);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	allowable_manifest->manifest_index = allowable_pfm_element.port_id;

	allowable_pfm_element.manifest.platform_id[allowable_pfm_element.manifest.platform_id_len] =
		'\0';
	allowable_manifest->platform_id = strdup ((char*) allowable_pfm_element.manifest.platform_id);
	if (allowable_manifest->platform_id == NULL) {
		return CFM_NO_MEMORY;
	}

	num_allowable_id = manifest_flash_get_num_child_elements (&cfm_flash->base_flash,
		cfm_flash->base_flash.hash, *element_entry_ptr, manifest_type, CFM_COMPONENT_DEVICE,
		CFM_ALLOWABLE_ID, NULL);
	if (ROT_IS_ERROR (num_allowable_id)) {
		status = num_allowable_id;
		goto free_manifest;
	}

	allowable_manifest->check_count = num_allowable_id;
	allowable_manifest->check = platform_calloc (allowable_manifest->check_count,
		sizeof (struct cfm_allowable_id));
	if (allowable_manifest->check == NULL) {
		status = CFM_NO_MEMORY;
		goto free_manifest;
	}

	for (i_allowable_id = 0; i_allowable_id < num_allowable_id; ++i_allowable_id) {
		status = manifest_flash_read_element_data (&cfm_flash->base_flash,
			cfm_flash->base_flash.hash,	CFM_ALLOWABLE_ID, *element_entry_ptr, manifest_type, 0,
			NULL, NULL, NULL, (uint8_t**) &allowable_id_element_ptr,
			sizeof (struct cfm_allowable_id_element));
		if (ROT_IS_ERROR (status)) {
			if (status == MANIFEST_CHILD_NOT_FOUND) {
				status = CFM_ELEMENT_NOT_FOUND;
			}

			goto free_manifest;
		}

		allowable_id_ptr = &allowable_manifest->check[i_allowable_id];
		allowable_id_ptr->check = allowable_id_element_ptr->check;
		allowable_id_ptr->id_count = allowable_id_element_ptr->num_id;

		offset = sizeof (struct cfm_allowable_id_element);

		ids_len = allowable_id_ptr->id_count * sizeof (uint32_t);

		allowable_id_ptr->allowable_id = platform_malloc (ids_len);
		if (allowable_id_ptr->allowable_id == NULL) {
			status = CFM_NO_MEMORY;
			goto free_manifest;
		}

		status = manifest_flash_read_element_data (&cfm_flash->base_flash,
			cfm_flash->base_flash.hash,	CFM_ALLOWABLE_ID, *element_entry_ptr, manifest_type, offset,
			element_entry_ptr, NULL, NULL, (uint8_t**) &allowable_id_ptr->allowable_id, ids_len);
		if (ROT_IS_ERROR (status)) {
			goto free_manifest;
		}

		*element_entry_ptr = *element_entry_ptr + 1;
	}

	return 0;

free_manifest:
	cfm_flash_free_manifest (cfm, allowable_manifest);

	return status;
}

int cfm_flash_get_next_pfm (struct cfm *cfm, const char *component_type,
	struct cfm_manifest *allowable_pfm, bool first)
{
	return cfm_flash_get_next_manifest (cfm, component_type, CFM_ALLOWABLE_PFM, allowable_pfm,
		first);
}

int cfm_flash_get_next_cfm (struct cfm *cfm, const char *component_type,
	struct cfm_manifest *allowable_cfm, bool first)
{
	return cfm_flash_get_next_manifest (cfm, component_type, CFM_ALLOWABLE_CFM, allowable_cfm,
		first);
}

int cfm_flash_get_pcd (struct cfm *cfm, const char *component_type,
	struct cfm_manifest *allowable_pcd)
{
	return cfm_flash_get_next_manifest (cfm, component_type, CFM_ALLOWABLE_PCD, allowable_pcd,
		true);
}

/**
 * Initialize the interface to a CFM residing in flash memory.
 *
 * @param cfm The CFM instance to initialize.
 * @param flash The flash device that contains the CFM.
 * @param hash A hash engine to use for validating run-time access to CFM information. If it is
 * possible for any CFM information to be requested concurrently by different threads, this hash
 * engine MUST be thread-safe. There is no internal synchronization around the hashing operations.
 * @param base_addr The starting address of the CFM storage location.
 * @param signature_cache Buffer to hold the manifest signature.
 * @param max_signature The maximum supported length for a manifest signature.
 * @param platform_id_cache Buffer to hold the manifest platform ID.
 * @param max_platform_id The maximum platform ID length supported, including the NULL terminator.
 *
 * @return 0 if the CFM instance was initialized successfully or an error code.
 */
int cfm_flash_init (struct cfm_flash *cfm, struct flash *flash, struct hash_engine *hash,
	uint32_t base_addr, uint8_t *signature_cache, size_t max_signature, uint8_t *platform_id_cache,
	size_t max_platform_id)
{
	int status;

	if ((cfm == NULL) || (signature_cache == NULL) || (platform_id_cache == NULL)) {
		return CFM_INVALID_ARGUMENT;
	}

	memset (cfm, 0, sizeof (struct cfm_flash));

	status = manifest_flash_v2_init (&cfm->base_flash, flash, hash, base_addr, CFM_MAGIC_NUM,
		CFM_V2_MAGIC_NUM, signature_cache, max_signature, platform_id_cache, max_platform_id);
	if (status != 0) {
		return status;
	}

	cfm->base.base.verify = cfm_flash_verify;
	cfm->base.base.get_id = cfm_flash_get_id;
	cfm->base.base.get_platform_id = cfm_flash_get_platform_id;
	cfm->base.base.free_platform_id = cfm_flash_free_platform_id;
	cfm->base.base.get_hash = cfm_flash_get_hash;
	cfm->base.base.get_signature = cfm_flash_get_signature;
	cfm->base.base.is_empty = cfm_flash_is_empty;

	cfm->base.get_component_device = cfm_flash_get_component_device;
	cfm->base.free_component_device = cfm_flash_free_component_device;
	cfm->base.buffer_supported_components = cfm_flash_buffer_supported_components;
	cfm->base.get_component_pmr = cfm_flash_get_component_pmr;
	cfm->base.get_component_pmr_digest = cfm_flash_get_component_pmr_digest;
	cfm->base.free_component_pmr_digest = cfm_flash_free_component_pmr_digest;
	cfm->base.get_next_measurement = cfm_flash_get_next_measurement;
	cfm->base.free_measurement = cfm_flash_free_measurement;
	cfm->base.get_next_measurement_data = cfm_flash_get_next_measurement_data;
	cfm->base.free_measurement_data = cfm_flash_free_measurement_data;
	cfm->base.get_root_ca_digest = cfm_flash_get_root_ca_digest;
	cfm->base.free_root_ca_digest = cfm_flash_free_root_ca_digest;
	cfm->base.get_next_pfm = cfm_flash_get_next_pfm;
	cfm->base.get_next_cfm = cfm_flash_get_next_cfm;
	cfm->base.get_pcd = cfm_flash_get_pcd;
	cfm->base.free_manifest = cfm_flash_free_manifest;

	return 0;
}

/**
 * Release the resources used by the CFM interface.
 *
 * @param cfm The CFM instance to release.
 */
void cfm_flash_release (struct cfm_flash *cfm)
{
	if (cfm != NULL) {
		manifest_flash_release (&cfm->base_flash);
	}
}
