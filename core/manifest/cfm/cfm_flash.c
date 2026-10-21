// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "cfm_flash.h"
#include "cfm_format.h"
#include "platform_api.h"
#include "common/buffer_util.h"
#include "common/common_math.h"
#include "common/unused.h"
#include "flash/flash_util.h"
#include "manifest/manifest_flash.h"


int cfm_flash_verify (const struct manifest *cfm, const struct hash_engine *hash,
	const struct signature_verification *verification, uint8_t *hash_out, size_t hash_length)
{
	const struct cfm_flash *cfm_flash = (const struct cfm_flash*) cfm;

	if (cfm_flash == NULL) {
		return CFM_INVALID_ARGUMENT;
	}

	return manifest_flash_verify (&cfm_flash->base_flash, hash, verification, hash_out,
		hash_length);
}

int cfm_flash_get_id (const struct manifest *cfm, uint32_t *id)
{
	const struct cfm_flash *cfm_flash = (const struct cfm_flash*) cfm;

	if (cfm_flash == NULL) {
		return CFM_INVALID_ARGUMENT;
	}

	return manifest_flash_get_id (&cfm_flash->base_flash, id);
}

int cfm_flash_get_platform_id (const struct manifest *cfm, char **id, size_t length)
{
	const struct cfm_flash *cfm_flash = (const struct cfm_flash*) cfm;

	if (cfm_flash == NULL) {
		return CFM_INVALID_ARGUMENT;
	}

	return manifest_flash_get_platform_id (&cfm_flash->base_flash, id, length);
}

void cfm_flash_free_platform_id (const struct manifest *manifest, char *id)
{
	UNUSED (manifest);
	UNUSED (id);

	/* Don't need to do anything.  Manifest allocated buffers use the internal static buffer. */
}

int cfm_flash_get_hash (const struct manifest *cfm, const struct hash_engine *hash,
	uint8_t *hash_out, size_t hash_length)
{
	const struct cfm_flash *cfm_flash = (const struct cfm_flash*) cfm;

	if (cfm_flash == NULL) {
		return CFM_INVALID_ARGUMENT;
	}

	return manifest_flash_get_hash (&cfm_flash->base_flash, hash, hash_out, hash_length);
}

int cfm_flash_get_signature (const struct manifest *cfm, uint8_t *signature, size_t length)
{
	const struct cfm_flash *cfm_flash = (const struct cfm_flash*) cfm;

	if (cfm_flash == NULL) {
		return CFM_INVALID_ARGUMENT;
	}

	return manifest_flash_get_signature (&cfm_flash->base_flash, signature, length);
}

int cfm_flash_is_empty (const struct manifest *cfm)
{
	const struct cfm_flash *cfm_flash = (const struct cfm_flash*) cfm;

	if (cfm_flash == NULL) {
		return CFM_INVALID_ARGUMENT;
	}

	if (!cfm_flash->base_flash.state->manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	/* Every CFM must have a platform ID.  If that is all we have, then it is an empty manifest. */
	return (cfm_flash->base_flash.state->entry_count == 1);
}

/**
 * Find component device element for the specified component ID.
 *
 * @param cfm_flash The CFM to query.
 * @param component_id The component ID to find.
 * @param component Output for the component device data.
 * @param entry Optional input for starting entry to use, then output for the entry index
 * 	following the matching component device element if found.  This can be null if not needed.
 *
 * @return 0 if the component device element was found or an error code.
 */
static int cfm_flash_get_component_device_with_starting_entry (const struct cfm_flash *cfm_flash,
	uint32_t component_id, struct cfm_component_device_element *component, int *entry)
{
	int element_entry = 0;
	int status;

	if ((cfm_flash == NULL) || (component == NULL)) {
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

		if (status < (int) (sizeof (struct cfm_component_device_element))) {
			return CFM_MALFORMED_COMPONENT_DEVICE_ENTRY;
		}
		else if (component->transcript_hash_type > MANIFEST_HASH_SHA512) {
			return CFM_INVALID_TRANSCRIPT_HASH_TYPE;
		}
		else if (component->measurement_hash_type > MANIFEST_HASH_SHA512) {
			return CFM_INVALID_MEASUREMENT_HASH_TYPE;
		}

		element_entry++;
	} while (component_id != component->component_id);

	if (entry != NULL) {
		*entry = element_entry;
	}

	return 0;
}

/**
 * Get PMR ID list for the specified entry.
 *
 * @param cfm_flash The CFM to query.
 * @param entry Starting entry to use.
 * @param pmr_list List of PMR IDs.
 *
 * @return The count of PMR IDs found or an error code.
 */
static int cfm_flash_get_pmr_id_list (const struct cfm_flash *cfm_flash, int entry,
	uint8_t **pmr_list)
{
	struct cfm_pmr_digest_element pmr_digest_element;
	struct cfm_pmr_digest_element *pmr_digest_element_ptr = &pmr_digest_element;
	int num_pmr_ids;
	int i_pmr_id;
	int status;

	status = manifest_flash_get_child_elements_info (&cfm_flash->base_flash,
		cfm_flash->base_flash.hash, entry, CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT, CFM_PMR_DIGEST,
		NULL, &num_pmr_ids, NULL);
	if (status != 0) {
		return status;
	}

	if (num_pmr_ids == 0) {
		*pmr_list = NULL;

		return 0;
	}

	*pmr_list = platform_malloc (sizeof (uint8_t) * num_pmr_ids);
	if (*pmr_list == NULL) {
		return CFM_NO_MEMORY;
	}

	for (i_pmr_id = 0; i_pmr_id < num_pmr_ids; ++i_pmr_id) {
		status = manifest_flash_read_element_data (&cfm_flash->base_flash,
			cfm_flash->base_flash.hash, CFM_PMR_DIGEST, entry, CFM_COMPONENT_DEVICE, 0, &entry,
			NULL, NULL, (uint8_t**) &pmr_digest_element_ptr,
			sizeof (struct cfm_pmr_digest_element));
		if (ROT_IS_ERROR (status)) {
			if (status == MANIFEST_CHILD_NOT_FOUND) {
				status = CFM_ENTRY_NOT_FOUND;
			}

			goto fail;
		}

		if (status < (int) (sizeof (struct cfm_pmr_digest_element))) {
			status = CFM_MALFORMED_PMR_DIGEST_ENTRY;

			goto fail;
		}

		(*pmr_list)[i_pmr_id] = pmr_digest_element.pmr_id;

		++entry;
	}

	return num_pmr_ids;

fail:
	platform_free (*pmr_list);
	*pmr_list = NULL;

	return status;
}

int cfm_flash_get_component_device (const struct cfm *cfm, uint32_t component_id,
	struct cfm_component_device *component)
{
	const struct cfm_flash *cfm_flash = (const struct cfm_flash*) cfm;
	struct cfm_component_device_element component_element;
	int entry = 0;
	int status;

	if (component == NULL) {
		return CFM_INVALID_ARGUMENT;
	}

	status = cfm_flash_get_component_device_with_starting_entry (cfm_flash, component_id,
		&component_element, &entry);
	if (status == 0) {
		component->attestation_protocol =
			(enum cfm_attestation_type) component_element.attestation_protocol;
		component->transcript_hash_type =
			manifest_convert_manifest_hash_type (component_element.transcript_hash_type);
		component->measurement_hash_type =
			manifest_convert_manifest_hash_type (component_element.measurement_hash_type);
		component->cert_slot = component_element.cert_slot;
		component->component_id = component_element.component_id;

		status = cfm_flash_get_pmr_id_list (cfm_flash, entry, (uint8_t**) &component->pmr_id_list);
		if (ROT_IS_ERROR (status)) {
			return status;
		}

		component->num_pmr_ids = status;

		return 0;
	}

	return status;
}

void cfm_flash_free_component_device (const struct cfm *cfm, struct cfm_component_device *component)
{
	UNUSED (cfm);

	if (component != NULL) {
		platform_free ((void*) component->pmr_id_list);
	}
}

int cfm_flash_buffer_supported_components (const struct cfm *cfm, size_t offset, size_t length,
	uint8_t *component_ids)
{
	const struct cfm_flash *cfm_flash = (const struct cfm_flash*) cfm;
	struct cfm_component_device_element component;
	uint8_t *component_ptr;
	size_t i_components = 0;
	size_t remaining_len = length;
	size_t component_len;
	int entry = 0;
	int status;

	if ((cfm_flash == NULL) || (component_ids == NULL) || (length == 0)) {
		return CFM_INVALID_ARGUMENT;
	}

	if (!cfm_flash->base_flash.state->manifest_valid) {
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

		if (status < (int) (sizeof (struct cfm_component_device_element))) {
			return CFM_MALFORMED_COMPONENT_DEVICE_ENTRY;
		}

		++entry;

		i_components += buffer_copy ((uint8_t*) &component.component_id,
			sizeof (component.component_id), &offset, &remaining_len, &component_ids[i_components]);
	}

done:

	return i_components;
}

/**
 * Common function used to get next element data for the specified component ID and element type.
 *
 * @param cfm_flash The CFM to query.
 * @param component_id The component ID used to locate the component device element when entry is
 *  NULL or when entry is not NULL but *entry == 0.  If entry is not NULL and *entry != 0, this
 *  parameter is ignored and the search continues from the provided entry index.
 * @param buffer A container to be updated with the pointer to requested element data.  If *buffer
 *  is NULL, a buffer will be dynamically allocated to fit the entire element.  This buffer must be
 *  freed by the caller.
 * @param buffer_len If *buffer is not NULL, this must be non-NULL and contains the length of the
 *  provided buffer on input.  On return, it is updated with the length of element data.
 *  If *buffer is NULL, this parameter is optional and can be NULL if not needed.
 * @param entry Optional input specifying the starting entry index.  If entry is NULL or *entry == 0,
 *  component_id will be used to locate the corresponding component device element and the search
 *  will start from its first child.  If entry is not NULL and *entry != 0, the search will start from
 *  the specified entry index.  On successful return, entry will be updated to the index following
 *  the matching element.
 * @param element_type Element type to retrieve.
 *
 * @return 0 if the element was found or an error code.
 */
static int cfm_flash_get_next_element (const struct cfm_flash *cfm_flash, uint32_t component_id,
	uint8_t **buffer, size_t *buffer_len, int *entry, int element_type)
{
	struct cfm_component_device_element component;
	int element_entry = 0;
	size_t *buffer_len_ptr = buffer_len;
	size_t buffer_len_buf;
	int num_element;
	int status;

	if ((cfm_flash == NULL) || (buffer == NULL) || ((*buffer != NULL) && (buffer_len == NULL))) {
		return CFM_INVALID_ARGUMENT;
	}

	if (!cfm_flash->base_flash.state->manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	if (entry != NULL) {
		element_entry = *entry;
	}

	if (element_entry == 0) {
		status = cfm_flash_get_component_device_with_starting_entry (cfm_flash, component_id,
			&component, &element_entry);
		if (status != 0) {
			return status;
		}
	}

	if (buffer_len == NULL) {
		buffer_len_ptr = &buffer_len_buf;
	}

	status = manifest_flash_get_child_elements_info (&cfm_flash->base_flash,
		cfm_flash->base_flash.hash, element_entry, CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT,
		element_type, NULL, &num_element, NULL);
	if (status != 0) {
		return status;
	}

	if (num_element == 0) {
		goto not_found;
	}

	status = manifest_flash_read_element_data (&cfm_flash->base_flash, cfm_flash->base_flash.hash,
		element_type, element_entry, CFM_COMPONENT_DEVICE, 0, &element_entry, NULL, buffer_len_ptr,
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

	return CFM_ENTRY_NOT_FOUND;
}

int cfm_flash_get_component_pmr (const struct cfm *cfm, uint32_t component_id, uint8_t pmr_id,
	struct cfm_pmr *pmr)
{
	const struct cfm_flash *cfm_flash = (const struct cfm_flash*) cfm;

	union {
		struct cfm_component_device_element component;
		struct cfm_pmr_element pmr_element;
	} buffer;
	struct cfm_component_device_element *component_ptr = &buffer.component;
	struct cfm_pmr_element *pmr_element_ptr = &buffer.pmr_element;
	size_t pmr_element_len;
	int entry = 0;
	enum hash_type hash_type;
	int hash_len;
	int status;

	if ((cfm == NULL) || (pmr == NULL)) {
		return CFM_INVALID_ARGUMENT;
	}

	status = cfm_flash_get_component_device_with_starting_entry (cfm_flash, component_id,
		component_ptr, &entry);
	if (status != 0) {
		return status;
	}

	hash_type = manifest_convert_manifest_hash_type (component_ptr->measurement_hash_type);

	while (1) {
		pmr_element_len = sizeof (struct cfm_pmr_element);

		status = cfm_flash_get_next_element (cfm_flash, component_id, (uint8_t**) &pmr_element_ptr,
			&pmr_element_len, &entry, CFM_PMR);
		if (status != 0) {
			if (status == CFM_ENTRY_NOT_FOUND) {
				return CFM_PMR_NOT_FOUND;
			}

			return status;
		}

		if (buffer.pmr_element.pmr_id == pmr_id) {
			hash_len = hash_get_hash_length (hash_type);
			if (ROT_IS_ERROR (hash_len)) {
				return hash_len;
			}

			pmr->pmr_id = buffer.pmr_element.pmr_id;
			pmr->initial_value_len = hash_len;
			pmr->hash_type = hash_type;

			memcpy ((void*) pmr->initial_value, buffer.pmr_element.initial_value, hash_len);

			return 0;
		}
	}
}

/**
 * Common function used to free cfm_digests container.
 *
 * @param cfm_flash The CFM to query.
 * @param digests The CFM digests container with content to free.
 */
static void cfm_flash_free_cfm_digests (const struct cfm_flash *cfm_flash,
	struct cfm_digests *digests)
{
	UNUSED (cfm_flash);

	platform_free ((void*) digests->digests);
	digests->digests = NULL;
}

/**
 * Free cfm_allowable_digests container.
 *
 * @param cfm_flash The CFM to query.
 * @param digests The CFM allowable digests container with content to free.
 */
static void cfm_flash_free_cfm_allowable_digests (const struct cfm_flash *cfm_flash,
	struct cfm_allowable_digests *allowable_digests, size_t allowable_digests_count)
{
	size_t i;

	if (allowable_digests == NULL) {
		return;
	}

	for (i = 0; i < allowable_digests_count; ++i) {
		cfm_flash_free_cfm_digests (cfm_flash, &allowable_digests[i].digests);
	}

	platform_free ((void*) allowable_digests);
}

/**
 * Common function used to read a list of digests from CFM entry and offset provided, then
 * generating a cfm_digests container with the output.
 *
 * @param cfm_flash The CFM to query.
 * @param digests The cfm_digests container to fill up.
 * @param digest_count The number of digests to read.
 * @param hash_type The type of digests to read.
 * @param element_type The type of element digests list is part of.
 * @param entry The entry number of the element being read.
 * @param offset The offset into the element being read the digests list is at.
 *
 * @return 0 if the container was generated successfully or an error code.
 */
static int cfm_flash_populate_digests (const struct cfm_flash *cfm_flash,
	struct cfm_digests *digests, size_t digest_count, enum hash_type hash_type,
	uint8_t element_type, int entry, uint32_t offset)
{
	size_t digests_len;
	int hash_len;
	int status;

	hash_len = hash_get_hash_length (hash_type);
	if (ROT_IS_ERROR (hash_len)) {
		return hash_len;
	}

	digests_len = hash_len * digest_count;

	digests->digests = platform_malloc (digests_len);
	if (digests->digests == NULL) {
		return CFM_NO_MEMORY;
	}

	digests->digest_count = digest_count;
	digests->hash_type = hash_type;

	status = manifest_flash_read_element_data (&cfm_flash->base_flash, cfm_flash->base_flash.hash,
		element_type, entry, CFM_COMPONENT_DEVICE, offset, NULL, NULL, NULL,
		(uint8_t**) &digests->digests, digests_len);
	if (ROT_IS_ERROR (status)) {
		if (status == MANIFEST_CHILD_NOT_FOUND) {
			status = CFM_ENTRY_MISSING_DIGESTS;
		}

		cfm_flash_free_cfm_digests (cfm_flash, digests);

		return status;
	}

	return 0;
}

/**
 * Read a list of Allowable Digests from CFM entry and offset provided, then generate a
 * cfm_allowable_digests container list with the output.
 * The caller is responsible for calling cfm_flash_free_cfm_allowable_digests()
 * to release any allocated memory in allowable_digests when this function
 * returns a non-zero status.
 *
 * @param cfm_flash The CFM to query.
 * @param allowable_digests The cfm_allowable_digests container list to fill up.
 * @param digest_count The number of digests to read.
 * @param element_type Manifest element tag that contains the allowable digest list.
 * @param default_hash_type The default hash type from the component device, used when an allowable
 * 	digest element does not specify its own hash type.
 * @param entry The entry number of the element being read.
 * @param offset The offset into the element being read the digests list is at.
 *
 * @return 0 if the container list was generated successfully or an error code.
 */
static int cfm_flash_populate_allowable_digests (const struct cfm_flash *cfm_flash,
	struct cfm_allowable_digests *allowable_digests, size_t allowable_digest_count,
	uint8_t element_type, enum hash_type default_hash_type, int entry, uint32_t offset)
{
	struct cfm_allowable_digest_element allowable_digest;
	struct cfm_allowable_digest_element *allowable_digest_ptr = &allowable_digest;
	struct cfm_allowable_digests *curr_allowable_digest;
	enum hash_type hash_type;
	size_t digests_len;
	size_t i_allowable_digest;
	int hash_len;
	int status;

	// Read each Allowable Digest and fill in allowable_digests
	for (i_allowable_digest = 0; i_allowable_digest < allowable_digest_count;
		i_allowable_digest++) {
		curr_allowable_digest = &allowable_digests[i_allowable_digest];

		// Read Allowable Digest information
		status = manifest_flash_read_element_data (&cfm_flash->base_flash,
			cfm_flash->base_flash.hash, element_type, entry, CFM_COMPONENT_DEVICE, offset, NULL,
			NULL, NULL, (uint8_t**) &allowable_digest_ptr,
			sizeof (struct cfm_allowable_digest_element));
		if (ROT_IS_ERROR (status)) {
			if (status == MANIFEST_CHILD_NOT_FOUND) {
				status = CFM_ENTRY_MISSING_DIGESTS;
			}

			return status;
		}

		if (status < (int) (sizeof (struct cfm_allowable_digest_element))) {
			return CFM_MALFORMED_MEASUREMENT_ENTRY;
		}

		// Determine hash type: component default unless the element specifies an override.
		hash_type = default_hash_type;

		if (allowable_digest_ptr->hash_type_override != 0) {
			// Aggregated digest size is fixed by the aggregation hash; per-element override is not allowed.
			if (element_type == CFM_AGGREGATED_MEASUREMENT) {
				return CFM_MALFORMED_MEASUREMENT_ENTRY;
			}

			hash_type = manifest_convert_manifest_hash_type (allowable_digest_ptr->hash_type);
		}

		hash_len = hash_get_hash_length (hash_type);
		if (ROT_IS_ERROR (hash_len)) {
			return hash_len;
		}

		// Get & set fields for current Allowable Digest
		curr_allowable_digest->version_set = allowable_digest_ptr->version_set;
		curr_allowable_digest->digests.hash_type = hash_type;
		curr_allowable_digest->digests.digest_count = allowable_digest_ptr->digest_count;

		if (curr_allowable_digest->digests.digest_count == 0) {
			return CFM_MALFORMED_MEASUREMENT_ENTRY;
		}

		digests_len = curr_allowable_digest->digests.digest_count * hash_len;

		// Advance to start of digests
		offset += sizeof (struct cfm_allowable_digest_element);

		// Allocate space for digests list
		curr_allowable_digest->digests.digests = platform_malloc (digests_len);
		if (curr_allowable_digest->digests.digests == NULL) {
			return CFM_NO_MEMORY;
		}

		// Read digests from current Allowable Digest element
		status = manifest_flash_read_element_data (&cfm_flash->base_flash,
			cfm_flash->base_flash.hash, element_type, entry, CFM_COMPONENT_DEVICE, offset, NULL,
			NULL, NULL, (uint8_t**) &curr_allowable_digest->digests.digests, digests_len);
		if (ROT_IS_ERROR (status)) {
			if (status == MANIFEST_CHILD_NOT_FOUND) {
				status = CFM_ENTRY_MISSING_DIGESTS;
			}

			return status;
		}

		if (status < (int) (digests_len)) {
			return CFM_MALFORMED_MEASUREMENT_ENTRY;
		}

		// Advance to start of cfm_allowable_digest_element
		offset += digests_len;
	}

	return 0;
}

void cfm_flash_free_component_pmr_digest (const struct cfm *cfm, struct cfm_pmr_digest *pmr_digest)
{
	const struct cfm_flash *cfm_flash = (const struct cfm_flash*) cfm;

	if (pmr_digest != NULL) {
		cfm_flash_free_cfm_digests (cfm_flash, &pmr_digest->digests);
	}
}

int cfm_flash_get_component_pmr_digest (const struct cfm *cfm, uint32_t component_id,
	uint8_t pmr_id, struct cfm_pmr_digest *pmr_digest)
{
	const struct cfm_flash *cfm_flash = (const struct cfm_flash*) cfm;

	union {
		struct cfm_component_device_element component;
		struct cfm_pmr_digest_element pmr_digest_element;
	} buffer;
	struct cfm_component_device_element *component_ptr = &buffer.component;
	struct cfm_pmr_digest_element *pmr_digest_element_ptr = &buffer.pmr_digest_element;
	size_t pmr_digest_element_len;
	int entry = 0;
	enum hash_type hash_type;
	int status;

	if (pmr_digest == NULL) {
		return CFM_INVALID_ARGUMENT;
	}

	status = cfm_flash_get_component_device_with_starting_entry (cfm_flash, component_id,
		component_ptr, &entry);
	if (status != 0) {
		return status;
	}

	hash_type = manifest_convert_manifest_hash_type (component_ptr->measurement_hash_type);

	while (1) {
		pmr_digest_element_len = sizeof (struct cfm_pmr_digest_element);

		status = cfm_flash_get_next_element (cfm_flash, component_id,
			(uint8_t**) &pmr_digest_element_ptr, &pmr_digest_element_len, &entry, CFM_PMR_DIGEST);
		if (status != 0) {
			if (status == CFM_ENTRY_NOT_FOUND) {
				return CFM_PMR_DIGEST_NOT_FOUND;
			}

			return status;
		}

		if (pmr_digest_element_len < sizeof (struct cfm_pmr_digest_element)) {
			return CFM_MALFORMED_PMR_DIGEST_ENTRY;
		}

		if (buffer.pmr_digest_element.pmr_id == pmr_id) {
			pmr_digest->pmr_id = buffer.pmr_digest_element.pmr_id;

			return cfm_flash_populate_digests (cfm_flash, &pmr_digest->digests,
				buffer.pmr_digest_element.digest_count, hash_type, CFM_PMR_DIGEST, entry - 1,
				sizeof (struct cfm_pmr_digest_element));
		}
	}
}

/**
 * Find next measurement entry after provided entry ID.
 *
 * @param cfm The CFM to query.
 * @param pmr_measurement A container to be updated with the component measurement information.
 * @param entry Entry ID to start from, then output for the entry index	following the matching
 * 	measurement element if found.
 *
 * @return 0 if the measurement was found or an error code.
 */
static int cfm_flash_get_next_measurement (const struct cfm *cfm,
	struct cfm_measurement_digest *pmr_measurement, enum hash_type default_hash_type, int *entry)
{
	const struct cfm_flash *cfm_flash = (const struct cfm_flash*) cfm;
	struct cfm_measurement_element measurement_element;
	struct cfm_measurement_element *measurement_element_ptr =
		(struct cfm_measurement_element*) &measurement_element;
	size_t measurement_element_len = sizeof (struct cfm_measurement_element);
	int status;

	pmr_measurement->allowable_digests = NULL;
	pmr_measurement->allowable_digests_count = 0;

	// Get the next Measurement element
	status = cfm_flash_get_next_element (cfm_flash, 0, (uint8_t**) &measurement_element_ptr,
		&measurement_element_len, entry, CFM_MEASUREMENT);
	if (status != 0) {
		return status;
	}

	// Verify that an entire Measurement element was read
	if (measurement_element_len < (int) (sizeof (struct cfm_measurement_element))) {
		return CFM_MALFORMED_MEASUREMENT_ENTRY;
	}

	pmr_measurement->pmr_id = measurement_element.pmr_id;
	pmr_measurement->measurement_id = measurement_element.measurement_id;
	pmr_measurement->allowable_digests_count = measurement_element.allowable_digest_count;
	pmr_measurement->allowable_digests = platform_calloc (pmr_measurement->allowable_digests_count,
		sizeof (struct cfm_allowable_digests));
	if (pmr_measurement->allowable_digests == NULL) {
		return CFM_NO_MEMORY;
	}

	// Retrieve list of cfm_allowable_digests
	status = cfm_flash_populate_allowable_digests (cfm_flash, pmr_measurement->allowable_digests,
		pmr_measurement->allowable_digests_count, CFM_MEASUREMENT, default_hash_type, *entry - 1,
		sizeof (struct cfm_measurement_element));
	if (status != 0) {
		cfm_flash_free_cfm_allowable_digests (cfm_flash, pmr_measurement->allowable_digests,
			pmr_measurement->allowable_digests_count);

		pmr_measurement->allowable_digests = NULL;
		pmr_measurement->allowable_digests_count = 0;
	}

	return status;
}

/**
 * Find next aggregated measurement entry after provided entry ID.
 *
 * @param cfm The CFM to query.
 * @param aggregated_measurement A container to be updated with the aggregated measurement
 * 	information.
 * @param entry Entry ID to start from, then output for the entry index following the matching
 * 	aggregated measurement element if found.
 *
 * @return 0 if the aggregated measurement was found or an error code.
 */
static int cfm_flash_get_next_aggregated_measurement (const struct cfm *cfm,
	struct cfm_aggregated_measurement *aggregated_measurement, int *entry)
{
	const struct cfm_flash *cfm_flash = (const struct cfm_flash*) cfm;
	struct cfm_aggregated_measurement_element measurement_element;
	struct cfm_aggregated_measurement_element *measurement_element_ptr =
		(struct cfm_aggregated_measurement_element*) &measurement_element;
	size_t measurement_element_len = sizeof (struct cfm_aggregated_measurement_element);
	int status;

	aggregated_measurement->allowable_digests = NULL;
	aggregated_measurement->allowable_digests_count = 0;

	// Get the next Aggregated Measurement element
	status = cfm_flash_get_next_element (cfm_flash, 0, (uint8_t**) &measurement_element_ptr,
		&measurement_element_len, entry, CFM_AGGREGATED_MEASUREMENT);
	if (status != 0) {
		return status;
	}

	// Verify that an entire Aggregated Measurement element was read
	if ((measurement_element_len < sizeof (struct cfm_aggregated_measurement_element)) ||
		(measurement_element.allowable_digest_count == 0)) {
		return CFM_MALFORMED_MEASUREMENT_ENTRY;
	}

	if (measurement_element.hash_type > MANIFEST_HASH_SHA512) {
		return CFM_INVALID_MEASUREMENT_HASH_TYPE;
	}

	memcpy (aggregated_measurement->measurements_mask, measurement_element.measurements_mask,
		sizeof (aggregated_measurement->measurements_mask));
	aggregated_measurement->pmr_id = measurement_element.pmr_id;
	aggregated_measurement->hash_type =
		manifest_convert_manifest_hash_type (measurement_element.hash_type);
	aggregated_measurement->allowable_digests_count = measurement_element.allowable_digest_count;
	aggregated_measurement->allowable_digests =
		platform_calloc (aggregated_measurement->allowable_digests_count,
		sizeof (struct cfm_allowable_digests));
	if (aggregated_measurement->allowable_digests == NULL) {
		return CFM_NO_MEMORY;
	}

	// Retrieve list of cfm_allowable_digests
	status = cfm_flash_populate_allowable_digests (cfm_flash,
		aggregated_measurement->allowable_digests, aggregated_measurement->allowable_digests_count,
		CFM_AGGREGATED_MEASUREMENT,	aggregated_measurement->hash_type, *entry - 1,
		sizeof (struct cfm_aggregated_measurement_element));
	if (status != 0) {
		cfm_flash_free_cfm_allowable_digests (cfm_flash, aggregated_measurement->allowable_digests,
			aggregated_measurement->allowable_digests_count);

		aggregated_measurement->allowable_digests = NULL;
		aggregated_measurement->allowable_digests_count = 0;
	}

	return status;
}

/**
 * Free content within a measurement data container.
 *
 * @param cfm The CFM instance that provided the measurement data.
 * @param measurement_data The measurement data container with content to free.
 */
static void cfm_flash_free_measurement_data (const struct cfm *cfm,
	struct cfm_measurement_data *measurement_data)
{
	size_t i_check;
	size_t i_data;
	struct cfm_allowable_data_entry *curr_allowable_data;

	UNUSED (cfm);

	if (measurement_data != NULL) {
		for (i_check = 0; i_check < measurement_data->data_checks_count; ++i_check) {
			platform_free ((void*) measurement_data->data_checks[i_check].bitmask);
			measurement_data->data_checks[i_check].bitmask = NULL;

			curr_allowable_data = measurement_data->data_checks[i_check].allowable_data;
			if (curr_allowable_data != NULL) {
				for (i_data = 0; i_data < measurement_data->data_checks[i_check].data_count;
					i_data++) {
					platform_free ((void*) curr_allowable_data[i_data].data);
					curr_allowable_data[i_data].data = NULL;
				}
			}

			platform_free (curr_allowable_data);
			measurement_data->data_checks[i_check].allowable_data = NULL;
		}

		platform_free (measurement_data->data_checks);

		measurement_data->data_checks = NULL;
		measurement_data->data_checks_count = 0;
	}
}

/**
 * Internal measurement container free function.  This function does not free container context.
 *
 * @param cfm The CFM instance that provided the measurement data.
 * @param measurement_data The measurement data container with content to free.
 */
static void cfm_flash_free_measurement_container_internal (const struct cfm *cfm,
	struct cfm_measurement_container *container)
{
	if (container != NULL) {
		if (container->measurement_type == CFM_MEASUREMENT_TYPE_DIGEST) {
			const struct cfm_flash *cfm_flash = (const struct cfm_flash*) cfm;

			cfm_flash_free_cfm_allowable_digests (cfm_flash,
				container->measurement.digest.allowable_digests,
				container->measurement.digest.allowable_digests_count);

			container->measurement.digest.allowable_digests = NULL;
		}
		else if (container->measurement_type == CFM_MEASUREMENT_TYPE_DATA) {
			cfm_flash_free_measurement_data (cfm, &container->measurement.data);
		}
		else if (container->measurement_type == CFM_MEASUREMENT_TYPE_AGGREGATED) {
			const struct cfm_flash *cfm_flash = (const struct cfm_flash*) cfm;

			cfm_flash_free_cfm_allowable_digests (cfm_flash,
				container->measurement.aggregated.allowable_digests,
				container->measurement.aggregated.allowable_digests_count);

			container->measurement.aggregated.allowable_digests = NULL;
		}
	}
}

void cfm_flash_free_measurement_container (const struct cfm *cfm,
	struct cfm_measurement_container *container)
{
	if ((cfm != NULL) && (container != NULL)) {
		cfm_flash_free_measurement_container_internal (cfm, container);
		platform_free (container->context);
		container->context = NULL;
	}
}

/**
 * Find next measurement data after provided entry ID.
 *
 * @param cfm The CFM to query.
 * @param measurement_data A container to be updated with the component measurement data
 * 	information.
 * @param entry Entry ID to start from, then output for the entry index	following the matching
 * 	measurement element if found.
 *
 * @return 0 if the measurement data was found or an error code.
 */
static int cfm_flash_get_next_measurement_data (const struct cfm *cfm,
	struct cfm_measurement_data *measurement_data, int *entry)
{
	const struct cfm_flash *cfm_flash = (const struct cfm_flash*) cfm;

	union {
		struct cfm_measurement_data_element measurement_data_element;
		struct cfm_allowable_data_element allowable_data_element;
		struct cfm_allowable_data_element_entry allowable_data_element_entry;
	} buffer;
	struct cfm_measurement_data_element *measurement_data_element_ptr =
		&buffer.measurement_data_element;
	struct cfm_allowable_data_element *allowable_data_element_ptr = &buffer.allowable_data_element;
	struct cfm_allowable_data_element_entry *allowable_data_element_entry_ptr =
		&buffer.allowable_data_element_entry;
	struct cfm_allowable_data *allowable_data_ptr;
	size_t measurement_data_element_len = sizeof (struct cfm_measurement_data_element);
	size_t offset;
	size_t i_data;
	int i_allowable_data;
	int num_allowable_data;
	int status;

	measurement_data->data_checks = NULL;
	measurement_data->data_checks_count = 0;

	// Get Measurement Data element
	status = cfm_flash_get_next_element (cfm_flash, 0, (uint8_t**) &measurement_data_element_ptr,
		&measurement_data_element_len, entry, CFM_MEASUREMENT_DATA);
	if (status != 0) {
		return status;
	}

	// Verify that an entire Measurement Data element was read
	if (measurement_data_element_len < (int) (sizeof (struct cfm_measurement_data_element))) {
		return CFM_MALFORMED_MEASUREMENT_DATA_ENTRY;
	}

	measurement_data->pmr_id = measurement_data_element_ptr->pmr_id;
	measurement_data->measurement_id = measurement_data_element_ptr->measurement_id;

	// Get count of Allowable Data elements
	status = manifest_flash_get_child_elements_info (&cfm_flash->base_flash,
		cfm_flash->base_flash.hash, *entry, CFM_MEASUREMENT_DATA, CFM_COMPONENT_DEVICE,
		CFM_ALLOWABLE_DATA, NULL, &num_allowable_data, NULL);
	if (status != 0) {
		return status;
	}

	// Allocate space for Allowable Datas and set fields of measurement_data
	measurement_data->data_checks_count = num_allowable_data;
	measurement_data->data_checks =
		platform_calloc (measurement_data->data_checks_count, sizeof (struct cfm_allowable_data));
	if (measurement_data->data_checks == NULL) {
		return CFM_NO_MEMORY;
	}

	// Read each Allowable Data element and fill in measurement_data
	for (i_allowable_data = 0; i_allowable_data < num_allowable_data; ++i_allowable_data) {
		// Read Allowable Data element
		status = manifest_flash_read_element_data (&cfm_flash->base_flash,
			cfm_flash->base_flash.hash, CFM_ALLOWABLE_DATA, *entry, CFM_MEASUREMENT_DATA, 0, NULL,
			NULL, NULL, (uint8_t**) &allowable_data_element_ptr,
			sizeof (struct cfm_allowable_data_element));
		if (ROT_IS_ERROR (status)) {
			if (status == MANIFEST_CHILD_NOT_FOUND) {
				status = CFM_ENTRY_NOT_FOUND;
			}

			goto free_allowable_data;
		}

		// Verify that an entire Allowable Data element was read
		if (status < (int) (sizeof (struct cfm_allowable_data_element))) {
			status = CFM_MALFORMED_ALLOWABLE_DATA_ENTRY;

			goto free_allowable_data;
		}

		allowable_data_ptr = &measurement_data->data_checks[i_allowable_data];
		allowable_data_ptr->check = (enum cfm_check) allowable_data_element_ptr->check.check;
		allowable_data_ptr->big_endian =
			(allowable_data_element_ptr->check.endianness == CFM_MULTIBYTE_BIG_ENDIAN);
		allowable_data_ptr->data_count = allowable_data_element_ptr->num_data;
		allowable_data_ptr->bitmask_length = allowable_data_element_ptr->bitmask_length;

		// Update offset to start of bitmask
		offset = sizeof (struct cfm_allowable_data_element);

		// Read bitmask, if one exists for this Allowable Data
		if (allowable_data_ptr->bitmask_length) {
			// Allocate space for bitmask
			allowable_data_ptr->bitmask = platform_malloc (allowable_data_ptr->bitmask_length);
			if (allowable_data_ptr->bitmask == NULL) {
				status = CFM_NO_MEMORY;
				goto free_allowable_data;
			}

			// Read bitmask from Allowable Data element
			status = manifest_flash_read_element_data (&cfm_flash->base_flash,
				cfm_flash->base_flash.hash, CFM_ALLOWABLE_DATA, *entry, CFM_MEASUREMENT_DATA,
				offset, NULL, NULL, NULL, (uint8_t**) &allowable_data_ptr->bitmask,
				allowable_data_ptr->bitmask_length);
			if (ROT_IS_ERROR (status)) {
				goto free_allowable_data;
			}

			// Ensure that the full bitmask was read
			if (status < (int) (allowable_data_ptr->bitmask_length)) {
				status = CFM_MALFORMED_ALLOWABLE_DATA_ENTRY;

				goto free_allowable_data;
			}

			// Advance offset for 4-byte alignment
			offset += (((size_t) allowable_data_ptr->bitmask_length + 3) & ~((size_t) 3));
		}

		// Allocate space for Data entries
		allowable_data_ptr->allowable_data = platform_calloc (allowable_data_ptr->data_count,
			sizeof (struct cfm_allowable_data_entry));
		if (allowable_data_ptr->allowable_data == NULL) {
			status = CFM_NO_MEMORY;
			goto free_allowable_data;
		}

		// Read all Data entries of current Allowable Data element
		for (i_data = 0; i_data < allowable_data_ptr->data_count; i_data++) {
			// Read Data header
			status = manifest_flash_read_element_data (&cfm_flash->base_flash,
				cfm_flash->base_flash.hash, CFM_ALLOWABLE_DATA, *entry, CFM_MEASUREMENT_DATA,
				offset, entry, NULL, NULL, (uint8_t**) &allowable_data_element_entry_ptr,
				sizeof (struct cfm_allowable_data_element_entry));
			if (ROT_IS_ERROR (status)) {
				goto free_allowable_data;
			}

			if (status < (int) (sizeof (struct cfm_allowable_data_element_entry))) {
				status = CFM_MALFORMED_ALLOWABLE_DATA_ENTRY;

				goto free_allowable_data;
			}

			allowable_data_ptr->allowable_data[i_data].version_set =
				allowable_data_element_entry_ptr->version_set;
			allowable_data_ptr->allowable_data[i_data].data_len =
				allowable_data_element_entry_ptr->data_length;

			offset += sizeof (struct cfm_allowable_data_element_entry);

			allowable_data_ptr->allowable_data[i_data].data =
				platform_malloc (allowable_data_ptr->allowable_data[i_data].data_len);
			if (allowable_data_ptr->allowable_data[i_data].data == NULL) {
				status = CFM_NO_MEMORY;
				goto free_allowable_data;
			}

			// Read Data
			status = manifest_flash_read_element_data (&cfm_flash->base_flash,
				cfm_flash->base_flash.hash, CFM_ALLOWABLE_DATA, *entry, CFM_MEASUREMENT_DATA,
				offset, entry, NULL, NULL,
				(uint8_t**) &allowable_data_ptr->allowable_data[i_data].data,
				allowable_data_ptr->allowable_data[i_data].data_len);
			if (ROT_IS_ERROR (status)) {
				goto free_allowable_data;
			}

			if (status < (int) (allowable_data_ptr->allowable_data[i_data].data_len)) {
				status = CFM_MALFORMED_ALLOWABLE_DATA_ENTRY;

				goto free_allowable_data;
			}

			offset += (((size_t) allowable_data_ptr->allowable_data[i_data].data_len + 3) &
				~((size_t) 3));
		}

		// Advance to next Allowable Data
		*entry = *entry + 1;
	}

	return 0;

free_allowable_data:
	cfm_flash_free_measurement_data (cfm, measurement_data);

	return status;
}

/**
 * Implementation context for the get_next_measurement_or_measurement_data function.
 */
struct cfm_flash_measurement_context {
	enum hash_type comp_device_hash_type;	/**< Hash type of component device. */
	int element_entry;						/**< Entry for next element to read back. */
	int first_measurement_entry;			/**< First Measurement child entry index. */
	int first_measurement_data_entry;		/**< First Measurement Data child entry index. */
	int first_aggregated_measurement_entry;	/**< First Aggregated Measurement child entry index. */
};


/**
 * Retrieve the first TOC entry indices for all measurement-related child elements.
 *
 * @param cfm The CFM instance to query.
 * @param context Measurement iteration context to be populated with child entry indices.
 * @param entry TOC entry index of the parent Component Device element.
 *
 * @return 0 if the child entry indices were retrieved successfully, or an error code.
 */
static int cfm_flash_get_first_measurement_child_entries (const struct cfm *cfm,
	struct cfm_flash_measurement_context *context, int entry)
{
	const struct cfm_flash *cfm_flash = (const struct cfm_flash*) cfm;
	int status;

	context->first_measurement_entry = INT_MAX;
	context->first_measurement_data_entry = INT_MAX;
	context->first_aggregated_measurement_entry = INT_MAX;

	status = manifest_flash_get_child_elements_info (&cfm_flash->base_flash,
		cfm_flash->base_flash.hash, entry, CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT,
		CFM_MEASUREMENT, NULL, NULL, &context->first_measurement_entry);
	if ((status != 0) && (status != MANIFEST_CHILD_NOT_FOUND)) {
		return status;
	}

	status = manifest_flash_get_child_elements_info (&cfm_flash->base_flash,
		cfm_flash->base_flash.hash, entry, CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT,
		CFM_MEASUREMENT_DATA, NULL, NULL, &context->first_measurement_data_entry);
	if ((status != 0) && (status != MANIFEST_CHILD_NOT_FOUND)) {
		return status;
	}

	status = manifest_flash_get_child_elements_info (&cfm_flash->base_flash,
		cfm_flash->base_flash.hash, entry, CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT,
		CFM_AGGREGATED_MEASUREMENT, NULL, NULL, &context->first_aggregated_measurement_entry);
	if ((status != 0) && (status != MANIFEST_CHILD_NOT_FOUND)) {
		return status;
	}

	return 0;
}

/**
 * Select the next measurement-related element type to process based on TOC order.
 *
 * @param container The measurement container to update with the selected measurement type.
 * @param context Iteration context containing cached TOC entry indices and the current
 *     iteration cursor.
 *
 * @return 0 if a next measurement element type was selected,
 *     MANIFEST_CHILD_NOT_FOUND if no further measurement elements exist.
 */
static int cfm_flash_select_next_measurement_container_type (
	struct cfm_measurement_container *container, struct cfm_flash_measurement_context *context)
{
	int next_entry = INT_MAX;
	int next_type = -1;

	if (context->first_measurement_entry != INT_MAX) {
		if ((context->first_measurement_entry < next_entry) &&
			(context->first_measurement_entry >= context->element_entry)) {
			next_type = CFM_MEASUREMENT;
			next_entry = context->first_measurement_entry;
		}
	}

	if (context->first_measurement_data_entry != INT_MAX) {
		if ((context->first_measurement_data_entry < next_entry) &&
			(context->first_measurement_data_entry >= context->element_entry)) {
			next_type = CFM_MEASUREMENT_DATA;
			next_entry = context->first_measurement_data_entry;
		}
	}

	if (context->first_aggregated_measurement_entry != INT_MAX) {
		if ((context->first_aggregated_measurement_entry < next_entry) &&
			(context->first_aggregated_measurement_entry >= context->element_entry)) {
			next_type = CFM_AGGREGATED_MEASUREMENT;
			next_entry = context->first_aggregated_measurement_entry;
		}
	}

	if (next_type == -1) {
		return MANIFEST_CHILD_NOT_FOUND;
	}

	switch (next_type) {
		case CFM_MEASUREMENT:
			container->measurement_type = CFM_MEASUREMENT_TYPE_DIGEST;
			break;

		case CFM_MEASUREMENT_DATA:
			container->measurement_type = CFM_MEASUREMENT_TYPE_DATA;
			break;

		case CFM_AGGREGATED_MEASUREMENT:
			container->measurement_type = CFM_MEASUREMENT_TYPE_AGGREGATED;
			break;
	}

	return 0;
}

/**
 * Determine if the unique element to be used to determine device version set is a Measurement,
 * Measurement Data, or Aggregated Measurement element.
 *
 * @param cfm The CFM to query.
 * @param component_id The component ID to find version set element for.
 * @param comp_device_entry Optional input for starting entry to use, then output for the entry
 *  index following the matching component device element if found.  This can be null if not needed.
 * @param comp_device_hash_type Buffer to update with component device hash type.
 *
 * @return Element tag used to determine version set, or an error code.
 */
static int cfm_flash_determine_version_set_element (const struct cfm *cfm, uint32_t component_id,
	struct cfm_measurement_container *container, struct cfm_flash_measurement_context *context)
{
	const struct cfm_flash *cfm_flash = (const struct cfm_flash*) cfm;
	struct cfm_component_device_element component_element;
	int entry = 0;
	int status;

	status = cfm_flash_get_component_device_with_starting_entry (cfm_flash, component_id,
		&component_element, &entry);
	if (status != 0) {
		return status;
	}

	context->comp_device_hash_type =
		manifest_convert_manifest_hash_type (component_element.measurement_hash_type);

	status = cfm_flash_get_first_measurement_child_entries (cfm, context, entry);
	if (status != 0) {
		return status;
	}
	context->element_entry = entry;

	return cfm_flash_select_next_measurement_container_type (container, context);
}

int cfm_flash_get_next_measurement_or_measurement_data (const struct cfm *cfm,
	uint32_t component_id, struct cfm_measurement_container *container, bool first)
{
	struct cfm_flash_measurement_context *context;
	int status;

	/* This function assumes all Measurement and Measurement Data entries are contiguous. */

	if ((cfm == NULL) || (container == NULL)) {
		return CFM_INVALID_ARGUMENT;
	}

	if (first) {
		memset (container, 0, sizeof (struct cfm_measurement_container));

		container->context = platform_calloc (sizeof (struct cfm_flash_measurement_context), 1);
		if (container->context == NULL) {
			return CFM_NO_MEMORY;
		}
		context = (struct cfm_flash_measurement_context*) container->context;

		status = cfm_flash_determine_version_set_element (cfm, component_id, container, context);
		if (status != 0) {
			platform_free (container->context);
			container->context = NULL;

			return status;
		}
	}
	else {
		cfm_flash_free_measurement_container_internal (cfm, container);
	}

	context = (struct cfm_flash_measurement_context*) container->context;

	// TODO: Support interleaved measurement and measurement block entries
	if (container->measurement_type == CFM_MEASUREMENT_TYPE_DIGEST) {
		status = cfm_flash_get_next_measurement (cfm, &container->measurement.digest,
			context->comp_device_hash_type, &context->element_entry);
	}
	else if (container->measurement_type == CFM_MEASUREMENT_TYPE_DATA) {
		status = cfm_flash_get_next_measurement_data (cfm, &container->measurement.data,
			&context->element_entry);
	}
	else {
		status = cfm_flash_get_next_aggregated_measurement (cfm, &container->measurement.aggregated,
			&context->element_entry);
	}

	if (status == CFM_ENTRY_NOT_FOUND) {
		status = cfm_flash_select_next_measurement_container_type (container, context);
		if (status == MANIFEST_CHILD_NOT_FOUND) {
			status = CFM_ENTRY_NOT_FOUND;
		}
		else {
			if (container->measurement_type == CFM_MEASUREMENT_TYPE_DIGEST) {
				status = cfm_flash_get_next_measurement (cfm, &container->measurement.digest,
					context->comp_device_hash_type, &context->element_entry);
			}
			else if (container->measurement_type == CFM_MEASUREMENT_TYPE_DATA) {
				status = cfm_flash_get_next_measurement_data (cfm, &container->measurement.data,
					&context->element_entry);
			}
			else {
				status = cfm_flash_get_next_aggregated_measurement (cfm,
					&container->measurement.aggregated,	&context->element_entry);
			}
		}
	}

	if ((status != 0) && first) {
		cfm_flash_free_measurement_container (cfm, container);
	}

	return status;
}

void cfm_flash_free_root_ca_digest (const struct cfm *cfm,
	struct cfm_root_ca_digests *root_ca_digest)
{
	const struct cfm_flash *cfm_flash = (const struct cfm_flash*) cfm;

	if (root_ca_digest != NULL) {
		cfm_flash_free_cfm_digests (cfm_flash, &root_ca_digest->digests);
	}
}

int cfm_flash_get_root_ca_digest (const struct cfm *cfm, uint32_t component_id,
	struct cfm_root_ca_digests *root_ca_digest)
{
	const struct cfm_flash *cfm_flash = (const struct cfm_flash*) cfm;

	union {
		struct cfm_component_device_element component;
		struct cfm_root_ca_digests_element root_ca_digests_element;
	} buffer;
	struct cfm_component_device_element *component_ptr = &buffer.component;
	struct cfm_root_ca_digests_element *root_ca_digests_element_ptr =
		&buffer.root_ca_digests_element;
	size_t root_ca_digests_element_len = sizeof (struct cfm_root_ca_digests_element);
	int entry = 0;
	enum hash_type hash_type;
	int status;

	if (root_ca_digest == NULL) {
		return CFM_INVALID_ARGUMENT;
	}

	status = cfm_flash_get_component_device_with_starting_entry (cfm_flash, component_id,
		component_ptr, &entry);
	if (status != 0) {
		return status;
	}

	hash_type = manifest_convert_manifest_hash_type (component_ptr->measurement_hash_type);

	status = cfm_flash_get_next_element (cfm_flash, component_id,
		(uint8_t**) &root_ca_digests_element_ptr, &root_ca_digests_element_len, &entry,
		CFM_ROOT_CA);
	if (status != 0) {
		if (status == CFM_ENTRY_NOT_FOUND) {
			return CFM_ROOT_CA_NOT_FOUND;
		}

		return status;
	}

	if (root_ca_digests_element_len < (int) (sizeof (struct cfm_root_ca_digests_element))) {
		return CFM_MALFORMED_ROOT_CA_DIGESTS_ENTRY;
	}

	return cfm_flash_populate_digests (cfm_flash, &root_ca_digest->digests,
		buffer.root_ca_digests_element.ca_count, hash_type, CFM_ROOT_CA, entry - 1,
		sizeof (struct cfm_root_ca_digests_element));
}

void cfm_flash_free_manifest (const struct cfm *cfm, struct cfm_manifest *manifest)
{
	size_t i_check;

	UNUSED (cfm);

	if (manifest != NULL) {
		for (i_check = 0; i_check < manifest->check_count; ++i_check) {
			platform_free ((void*) manifest->check[i_check].allowable_id);
		}

		platform_free (manifest->check);
		platform_free ((void*) manifest->platform_id);

		manifest->check_count = 0;
		manifest->check = NULL;
		manifest->platform_id = NULL;
	}
}

/**
 * Common function used to find next allowable manifest element for the specified component ID.
 *
 * @param cfm The CFM to query.
 * @param component_id The component ID to find allowable manifest for.
 * @param manifest_type The manifest type to find.
 * @param allowable_manifest A container to be updated with the component allowable manifest
 * 	information.  Contents of the container are dynamically allocated and need to be freed using
 * 	free_manifest.
 * @param first Fetch first allowable manifest from CFM, or next allowable manifest since last call.
 *
 * @return 0 if the allowable manifest element was found or an error code.
 */
static int cfm_flash_get_next_manifest (const struct cfm *cfm, uint32_t component_id,
	int manifest_type, struct cfm_manifest *allowable_manifest, bool first)
{
	const struct cfm_flash *cfm_flash = (const struct cfm_flash*) cfm;

	union {
		struct cfm_allowable_pfm_element allowable_pfm_element;
		struct cfm_allowable_id_element allowable_id_element;
	} buffer;
	struct cfm_allowable_pfm_element *allowable_pfm_element_ptr = &buffer.allowable_pfm_element;
	struct cfm_allowable_id_element *allowable_id_element_ptr = &buffer.allowable_id_element;
	struct cfm_allowable_id *allowable_id_ptr;
	size_t allowable_pfm_element_len = sizeof (struct cfm_allowable_pfm_element);
	size_t ids_len;
	size_t offset;
	size_t i_id;
	int *element_entry_ptr;
	int num_allowable_id;
	int i_allowable_id;
	int status;

	if ((cfm == NULL) || (allowable_manifest == NULL)) {
		return CFM_INVALID_ARGUMENT;
	}

	element_entry_ptr = (int*) &allowable_manifest->context;

	if (first) {
		*element_entry_ptr = 0;
	}
	else {
		cfm_flash_free_manifest (cfm, allowable_manifest);
	}

	allowable_manifest->check_count = 0;
	allowable_manifest->check = NULL;
	allowable_manifest->platform_id = NULL;

	// All allowable manifest elements have the same format, so use allowable PFM element containers
	status = cfm_flash_get_next_element (cfm_flash, component_id,
		(uint8_t**) &allowable_pfm_element_ptr, &allowable_pfm_element_len, element_entry_ptr,
		manifest_type);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	allowable_manifest->manifest_index = allowable_pfm_element_ptr->port_id;

	allowable_pfm_element_ptr->manifest.platform_id[
		allowable_pfm_element_ptr->manifest.platform_id_len] = '\0';
	allowable_manifest->platform_id =
		strdup ((char*) allowable_pfm_element_ptr->manifest.platform_id);
	if (allowable_manifest->platform_id == NULL) {
		return CFM_NO_MEMORY;
	}

	status = manifest_flash_get_child_elements_info (&cfm_flash->base_flash,
		cfm_flash->base_flash.hash, *element_entry_ptr, manifest_type, CFM_COMPONENT_DEVICE,
		CFM_ALLOWABLE_ID, NULL, &num_allowable_id, NULL);
	if (status != 0) {
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
		// Read Allowable ID element
		status = manifest_flash_read_element_data (&cfm_flash->base_flash,
			cfm_flash->base_flash.hash, CFM_ALLOWABLE_ID, *element_entry_ptr, manifest_type, 0,
			NULL, NULL, NULL, (uint8_t**) &allowable_id_element_ptr,
			sizeof (struct cfm_allowable_id_element));
		if (ROT_IS_ERROR (status)) {
			if (status == MANIFEST_CHILD_NOT_FOUND) {
				status = CFM_ENTRY_NOT_FOUND;
			}

			goto free_manifest;
		}

		if (status < (int) (sizeof (struct cfm_allowable_id_element))) {
			status = CFM_MALFORMED_ALLOWABLE_ID_ENTRY;

			goto free_manifest;
		}

		allowable_id_ptr = &allowable_manifest->check[i_allowable_id];
		allowable_id_ptr->check = (enum cfm_check) allowable_id_element_ptr->check.check;
		allowable_id_ptr->id_count = allowable_id_element_ptr->num_id;

		offset = sizeof (struct cfm_allowable_id_element);

		ids_len = allowable_id_ptr->id_count * sizeof (uint32_t);

		allowable_id_ptr->allowable_id = platform_malloc (ids_len);
		if (allowable_id_ptr->allowable_id == NULL) {
			status = CFM_NO_MEMORY;
			goto free_manifest;
		}

		// Read each ID
		status = manifest_flash_read_element_data (&cfm_flash->base_flash,
			cfm_flash->base_flash.hash, CFM_ALLOWABLE_ID, *element_entry_ptr, manifest_type, offset,
			element_entry_ptr, NULL, NULL, (uint8_t**) &allowable_id_ptr->allowable_id, ids_len);
		if (ROT_IS_ERROR (status)) {
			goto free_manifest;
		}

		if (status < (int) (ids_len)) {
			status = CFM_MALFORMED_ALLOWABLE_ID_ENTRY;

			goto free_manifest;
		}

		if (allowable_id_element_ptr->check.endianness == CFM_MULTIBYTE_BIG_ENDIAN) {
			for (i_id = 0; i_id < allowable_id_ptr->id_count; i_id++) {
				*((uint32_t*) &allowable_id_ptr->allowable_id[i_id]) =
					common_math_swap_bytes_uint32 (allowable_id_ptr->allowable_id[i_id]);
			}
		}

		*element_entry_ptr = *element_entry_ptr + 1;
	}

	return 0;

free_manifest:
	cfm_flash_free_manifest (cfm, allowable_manifest);

	return status;
}

int cfm_flash_get_next_pfm (const struct cfm *cfm, uint32_t component_id,
	struct cfm_manifest *allowable_pfm, bool first)
{
	return cfm_flash_get_next_manifest (cfm, component_id, CFM_ALLOWABLE_PFM, allowable_pfm, first);
}

int cfm_flash_get_next_cfm (const struct cfm *cfm, uint32_t component_id,
	struct cfm_manifest *allowable_cfm, bool first)
{
	return cfm_flash_get_next_manifest (cfm, component_id, CFM_ALLOWABLE_CFM, allowable_cfm, first);
}

int cfm_flash_get_pcd (const struct cfm *cfm, uint32_t component_id,
	struct cfm_manifest *allowable_pcd)
{
	return cfm_flash_get_next_manifest (cfm, component_id, CFM_ALLOWABLE_PCD, allowable_pcd, true);
}

/**
 * Initialize the interface to a CFM residing in flash memory.  CFMs support manifest version
 * 2 and 3.
 *
 * @param cfm The CFM instance to initialize.
 * @param state Variable context for the CFM instance.  This must be uninitialized.
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
int cfm_flash_init (struct cfm_flash *cfm, struct cfm_flash_state *state, const struct flash *flash,
	const struct hash_engine *hash, uint32_t base_addr, uint8_t *signature_cache,
	size_t max_signature, uint8_t *platform_id_cache, size_t max_platform_id)
{
	int status;

	if ((cfm == NULL) || (state == NULL)) {
		return CFM_INVALID_ARGUMENT;
	}

	memset (cfm, 0, sizeof (struct cfm_flash));

	status = manifest_flash_v3_init (&cfm->base_flash, &state->base, flash, hash, base_addr,
		MANIFEST_NOT_SUPPORTED, CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM, signature_cache, max_signature,
		platform_id_cache, max_platform_id);
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
	cfm->base.get_next_measurement_or_measurement_data =
		cfm_flash_get_next_measurement_or_measurement_data;
	cfm->base.free_measurement_container = cfm_flash_free_measurement_container;
	cfm->base.get_root_ca_digest = cfm_flash_get_root_ca_digest;
	cfm->base.free_root_ca_digest = cfm_flash_free_root_ca_digest;
	cfm->base.get_next_pfm = cfm_flash_get_next_pfm;
	cfm->base.get_next_cfm = cfm_flash_get_next_cfm;
	cfm->base.get_pcd = cfm_flash_get_pcd;
	cfm->base.free_manifest = cfm_flash_free_manifest;

	return 0;
}

/**
 * Initialize only the variable state for a CFM on flash.  The rest of the handler is assumed to
 * have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param cfm The CFM that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int cfm_flash_init_state (const struct cfm_flash *cfm)
{
	if (cfm == NULL) {
		return CFM_INVALID_ARGUMENT;
	}

	return manifest_flash_init_state (&cfm->base_flash);
}

/**
 * Release the resources used by the CFM interface.
 *
 * @param cfm The CFM instance to release.
 */
void cfm_flash_release (const struct cfm_flash *cfm)
{
	if (cfm != NULL) {
		manifest_flash_release (&cfm->base_flash);
	}
}
