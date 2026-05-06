"""
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the MIT license.
"""

from __future__ import print_function
from __future__ import unicode_literals
import os
import sys
import ctypes
import binascii
import argparse
import manifest_types
import manifest_common
import manifest_parser
from Crypto.PublicKey import RSA

CFM_CONFIG_FILENAME = "cfm_generator.config"


def generate_root_ca_digests (xml_root_ca_digests, measurement_hash_type):
    """
    Create a buffer of a Root CA digest struct instance from parsed XML list

    :param xml_root_ca_digests: List of parsed XML of root CA digests to be included in CFM
    :param measurement_hash_type: Hash type for Root CA digests

    :return (Root CA digest element, it's ToC entry)
    """

    digest_len = manifest_common.get_hash_len (measurement_hash_type)
    allowable_digests = []

    for digest in xml_root_ca_digests["allowable_digests"]:
        if len (digest) != digest_len:
            raise ValueError ("Hash of type '{0}' has unexpected length {1} vs {2}".format (
                measurement_hash_type, len (digest), digest_len))
        
        allowable_digests.append(digest)

    num_digests = len(allowable_digests)
    digests_buf = (ctypes.c_ubyte * (digest_len * num_digests)).from_buffer_copy(b''.join(allowable_digests))
    class cfm_root_ca_digest_element (ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('ca_count', ctypes.c_ubyte),
                    ('reserved', ctypes.c_ubyte * 3),
                    ('digests', ctypes.c_ubyte * ctypes.sizeof(digests_buf))]
    
    root_ca_digests = cfm_root_ca_digest_element (num_digests, (ctypes.c_ubyte * 3) (), digests_buf)
    root_ca_digests_len = ctypes.sizeof (root_ca_digests)

    root_ca_digests_toc_entry = manifest_common.manifest_toc_entry (
        manifest_common.CFM_V2_ROOT_CA_TYPE_ID,
        manifest_common.CFM_V2_COMPONENT_DEVICE_TYPE_ID, 0, 0, 0, root_ca_digests_len)

    return (root_ca_digests, root_ca_digests_toc_entry)

def generate_pmr (xml_pmr, measurement_hash_type):
    """
    Create a buffer of PMR section struct instances from parsed XML list

    :param xml_pmr: List of parsed XML of PMRs to be included in CFM
    :param measurement_hash_type: Hash type for PMR value

    :return List of (PMR element, ToC entry) tuples
    """

    pmrs_list = []
    digest_len = manifest_common.get_hash_len (measurement_hash_type)

    class cfm_pmr_element (ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('pmr_id', ctypes.c_ubyte),
                    ('reserved', ctypes.c_ubyte * 3),
                    ('initial_value', ctypes.c_ubyte * digest_len)]

    for pmr_id, pmr_dict in xml_pmr.items ():
        if len (pmr_dict["initial_value"]) != digest_len:
            raise ValueError ("Initial value of PMR '{0}' has unexpected length {1} vs {2}".format (
                pmr_id, len (pmr_dict["initial_value"]), digest_len))

        initial_value_arr = (ctypes.c_ubyte * digest_len).from_buffer_copy (
            pmr_dict["initial_value"])

        pmr = cfm_pmr_element (pmr_id, (ctypes.c_ubyte * 3) (), initial_value_arr)
        pmr_len = ctypes.sizeof (pmr)

        pmr_toc_entry = manifest_common.manifest_toc_entry (
            manifest_common.CFM_V2_PMR_TYPE_ID, manifest_common.CFM_V2_COMPONENT_DEVICE_TYPE_ID, 0,
            0, 0, pmr_len)

        pmrs_list.append ((pmr, pmr_toc_entry))

    return pmrs_list

def generate_pmr_digests (xml_pmr_digests, measurement_hash_type):
    """
    Create a buffer of PMR digests section struct instances from parsed XML list

    :param xml_pmr_digests: List of parsed XML of PMR digests to be included in CFM
    :param measurement_hash_type: Hash type for PMR digests

    :return List of (PMR digest element, ToC entry) tuples
    """

    pmr_digests_list = []
    digest_len = manifest_common.get_hash_len (measurement_hash_type)

    for pmr_id, pmr_digest_dict in xml_pmr_digests.items ():
        num_digests = len (pmr_digest_dict["allowable_digests"])
        digests_buf = (ctypes.c_ubyte * (digest_len * num_digests)) ()
        digests_len = 0

        for digest in pmr_digest_dict["allowable_digests"]:
            if len (digest) != digest_len:
                raise ValueError ("Hash of type '{0}' has unexpected length {1} vs {2}".format (
                    measurement_hash_type, len (digest), digest_len))

            digest_arr = (ctypes.c_ubyte * digest_len).from_buffer_copy (digest)
            ctypes.memmove (ctypes.addressof (digests_buf) + digests_len, digest_arr, digest_len)
            digests_len += digest_len

        class cfm_pmr_digest_element (ctypes.LittleEndianStructure):
            _pack_ = 1
            _fields_ = [('pmr_id', ctypes.c_ubyte),
                        ('num_digests', ctypes.c_ubyte),
                        ('reserved', ctypes.c_uint16),
                        ('digests', ctypes.c_ubyte * digests_len)]

        pmr_digest = cfm_pmr_digest_element (pmr_id, num_digests, 0, digests_buf)
        pmr_digest_len = ctypes.sizeof (pmr_digest)

        pmr_digest_toc_entry = manifest_common.manifest_toc_entry (
            manifest_common.CFM_V2_PMR_DIGEST_TYPE_ID,
            manifest_common.CFM_V2_COMPONENT_DEVICE_TYPE_ID, 0, 0, 0, pmr_digest_len)

        pmr_digests_list.append ((pmr_digest, pmr_digest_toc_entry))

    return pmr_digests_list

def analyze_measurements_for_aggregation(xml_measurements, unique):
    """
    Analyze measurements and separate them into aggregatable and non-aggregatable groups

    Version_set 0 is special - it applies to all version_sets and participates in aggregation
    for all version_sets.

    If unique==0, the first measurement (first by insertion order) with all its digests
    across all version sets is unconditionally placed into regular_measurements.

    :param xml_measurements: Measurements dictionary from XML

    :return Tuple of (aggregated_measurements, regular_measurements)
    """
    # aggregated_measurements: pmr_id -> version_set -> {"hash_type": int, "measurements": {measurement_id -> [digest]}}
    aggregated_measurements = {}
    # regular_measurements: pmr_id -> measurement_id -> version_set -> {"hash_type": int, "allowable_digests": [...]}
    regular_measurements = {}
    # Temporary structure to collect potentially aggregatable measurements
    # pmr_id -> version_set -> {"hash_type": int, "measurements": {measurement_id -> [digests]}}
    temp_aggregatable = {}

    # Determine the first measurement (by insertion order) to force into
    # regular_measurements when unique == 0
    forced_regular_key = None
    if unique == 0:
        for pmr_id, measurement_entries_dict in xml_measurements.items():
            for measurement_id in measurement_entries_dict.keys():
                forced_regular_key = (pmr_id, measurement_id)
                break
            if forced_regular_key is not None:
                break

    # First pass: separate aggregatable from non-aggregatable
    for pmr_id, measurement_entries_dict in xml_measurements.items():
        for measurement_id, version_sets_dict in measurement_entries_dict.items():
            # If unique==0, force the first measurement unconditionally into regular_measurements
            is_forced_regular = (forced_regular_key is not None and
                                 (pmr_id, measurement_id) == forced_regular_key)

            for version_set, measurements in version_sets_dict["version_set"].items():
                num_digests = len(measurements["allowable_digests"])

                if is_forced_regular or num_digests != 1:
                    # Forced regular (first measurement when unique==0) or
                    # non-aggregatable (multiple digests) - add to regular_measurements
                    if pmr_id not in regular_measurements:
                        regular_measurements[pmr_id] = {}
                    if measurement_id not in regular_measurements[pmr_id]:
                        regular_measurements[pmr_id][measurement_id] = {"version_set": {}}

                    regular_measurements[pmr_id][measurement_id]["version_set"][version_set] = \
                        measurements.copy()
                else:
                    # Potentially aggregatable - collect in temp structure
                    if pmr_id not in temp_aggregatable:
                        temp_aggregatable[pmr_id] = {}
                    if version_set not in temp_aggregatable[pmr_id]:
                        temp_aggregatable[pmr_id][version_set] = {
                            "hash_type": measurements["hash_type"],
                            "measurements": {}
                        }
                    temp_aggregatable[pmr_id][version_set]["measurements"][measurement_id] = \
                        measurements["allowable_digests"].copy()

    # Second pass: determine which potentially aggregatable measurements can actually be aggregated
    for pmr_id, version_sets_dict in temp_aggregatable.items():
        # Get version_set 0 data (common measurements that apply to all version_sets)
        version_set_0_data = version_sets_dict.get(0, {})
        version_set_0_measurements = version_set_0_data.get("measurements", {})
        num_version_set_0 = len(version_set_0_measurements)

        # Always add version_set 0 measurements to regular_measurements
        if 0 in version_sets_dict:
            hash_type_val = version_set_0_data["hash_type"]
            for measurement_id, measurement_digests in version_set_0_measurements.items():
                if pmr_id not in regular_measurements:
                    regular_measurements[pmr_id] = {}
                if measurement_id not in regular_measurements[pmr_id]:
                    regular_measurements[pmr_id][measurement_id] = {"version_set": {}}
                regular_measurements[pmr_id][measurement_id]["version_set"][0] = {
                    "hash_type": hash_type_val,
                    "allowable_digests": measurement_digests.copy()
                }

        # Process other version_sets
        for version_set, measurements_dict in version_sets_dict.items():
            if version_set == 0:
                continue  # Already processed above

            num_measurements = len(measurements_dict["measurements"])

            # Total measurements for this version_set = measurements in this version_set + version_set 0
            total_measurements_for_aggregation = num_measurements + num_version_set_0

            hash_type_val = measurements_dict["hash_type"]

            if total_measurements_for_aggregation >= 2:
                # Can be aggregated - combine measurements from this version_set and version_set 0
                if pmr_id not in aggregated_measurements:
                    aggregated_measurements[pmr_id] = {}

                # Combine measurements from version_set 0 and current version_set
                combined_measurements = {}

                # Add measurements from version_set 0
                for measurement_id, measurement_digests in version_set_0_measurements.items():
                    combined_measurements[measurement_id] = measurement_digests.copy()

                # Add measurements from current version_set
                for measurement_id, measurement_digests in measurements_dict["measurements"].items():
                    combined_measurements[measurement_id] = measurement_digests.copy()

                if version_set not in aggregated_measurements[pmr_id]:
                    aggregated_measurements[pmr_id][version_set] = {
                        "hash_type": hash_type_val,
                        "measurements": {}
                    }

                aggregated_measurements[pmr_id][version_set]["measurements"] = \
                    combined_measurements.copy()
            else:
                # Cannot aggregate - only one measurement total, move to regular_measurements
                for measurement_id, measurement_digests in measurements_dict["measurements"].items():
                    if pmr_id not in regular_measurements:
                        regular_measurements[pmr_id] = {}
                    if measurement_id not in regular_measurements[pmr_id]:
                        regular_measurements[pmr_id][measurement_id] = {"version_set": {}}

                    regular_measurements[pmr_id][measurement_id]["version_set"][version_set] = {
                        "hash_type": hash_type_val,
                        "allowable_digests": measurement_digests.copy()
                    }

    return aggregated_measurements, regular_measurements

def aggregate_measurements_hash(measurement_digests, hash_engine):
    """
    Aggregate multiple measurement digests into a single hash

    :param measurement_digests: List of digests to aggregate
    :param hash_engine: Hashing engine (SHA256, SHA384, or SHA512 class)

    :return Aggregated hash bytes
    """
    # Concatenate all digests and hash them together
    combined = b''.join(measurement_digests)
    # Create new hash instance and compute digest
    hash_obj = hash_engine.new(combined)
    aggregated_hash = hash_obj.digest()
    return aggregated_hash

def generate_aggregated_measurements(aggregated_measurements_data, hash_type, measurement_hash_type):
    """
    Create a buffer of aggregated measurements section struct instances

    Structure of input:
        pmr_id -> version_set -> {"hash_type": int, "measurements": {measurement_id -> [digest]}}

    :param aggregated_measurements_data: Dictionary of aggregated measurements data
    :param hash_type: Hashing type from cfm_generator.config
    :param measurement_hash_type: Default hash type for measurement digests (component-level)

    :return List of (Aggregated measurement element, ToC entry) tuples
    """
    aggregated_list = []

    # Temporary dictionary: pmr_id -> measurements_mask_bytes -> list of cfm_allowable_digest_element
    temp_dict = {}

    hash_engine = manifest_common.get_hash_engine(hash_type)
    hash_len = manifest_common.get_hash_len(hash_type)

    # Step 1: Create cfm_allowable_digest_element for each (pmr_id, version_set) and group by mask
    for pmr_id, version_sets_dict in aggregated_measurements_data.items():
        for version_set, measurements_dict in version_sets_dict.items():
            # Get sorted measurement IDs
            measurement_ids = sorted(measurements_dict["measurements"].keys())

            if "hash_type" not in measurements_dict:
                raise KeyError (
                    "Version set {0} for PMR {1} is missing required 'hash_type'".format (
                        version_set, pmr_id))
            vs_hash_type = measurements_dict["hash_type"]
            digest_len = manifest_common.get_hash_len(vs_hash_type)

            # Create measurements mask (256 bits = 32 bytes)
            measurements_mask = bytearray(32)
            for measurement_id in measurement_ids:
                byte_idx = measurement_id // 8
                bit_idx = measurement_id % 8
                measurements_mask[byte_idx] |= (1 << bit_idx)

            # Convert mask to bytes for use as dictionary key
            measurements_mask_bytes = bytes(measurements_mask)

            # Collect all digests for this version_set and aggregate them
            digests_to_aggregate = []
            for measurement_id in measurement_ids:
                digest = measurements_dict["measurements"][measurement_id][0]
                if len(digest) != digest_len:
                    raise ValueError("Hash has unexpected length {0} vs {1}".format(
                        len(digest), digest_len))
                digests_to_aggregate.append(digest)

            # Aggregate the digests
            aggregated_digest = aggregate_measurements_hash(digests_to_aggregate, hash_engine)
            digest_arr = (ctypes.c_ubyte * hash_len).from_buffer_copy(aggregated_digest)

            # Encode hash type override: flag + manifest_hash_type value
            hash_type_override = 0 if vs_hash_type == measurement_hash_type else 1
            hash_type_field = vs_hash_type if hash_type_override else 0

            # Create cfm_allowable_digest_element for this version_set
            class cfm_allowable_digest_element(ctypes.LittleEndianStructure):
                _pack_ = 1
                _fields_ = [('version_set', ctypes.c_uint16),
                             ('digest_count', ctypes.c_ubyte),
                             ('hash_type_override', ctypes.c_ubyte, 1),
                             ('hash_type', ctypes.c_ubyte, 7),
                             ('digest', ctypes.c_ubyte * hash_len)]

            allowable_digest = cfm_allowable_digest_element(
                version_set, 1, hash_type_override, hash_type_field, digest_arr)

            # Add to temporary dictionary
            if pmr_id not in temp_dict:
                temp_dict[pmr_id] = {}
            if measurements_mask_bytes not in temp_dict[pmr_id]:
                temp_dict[pmr_id][measurements_mask_bytes] = []

            temp_dict[pmr_id][measurements_mask_bytes].append(allowable_digest)

    # Step 2: Create cfm_aggregated_measurement_element for each (pmr_id, measurements_mask) group
    for pmr_id, mask_dict in temp_dict.items():
        for measurements_mask_bytes, allowable_digest_list in mask_dict.items():
            # Convert mask bytes back to ctypes array
            measurements_mask_arr = (ctypes.c_ubyte * 32).from_buffer_copy(measurements_mask_bytes)

            # Calculate total length for all allowable_digest elements
            allowable_digest_len = sum(ctypes.sizeof(d) for d in allowable_digest_list)

            # Create buffer for all allowable digest elements
            allowable_digest_buf = (ctypes.c_ubyte * allowable_digest_len)()
            manifest_common.move_list_to_buffer(allowable_digest_buf, 0, allowable_digest_list)

            class cfm_aggregated_measurement_element(ctypes.LittleEndianStructure):
                _pack_ = 1
                _fields_ = [('measurements_mask', ctypes.c_ubyte * 32),
                             ('pmr_id', ctypes.c_ubyte),
                             ('hash_type', ctypes.c_ubyte),
                             ('allowable_digest_count', ctypes.c_ubyte),
                             ('reserved', ctypes.c_ubyte),
                             ('digests_list', ctypes.c_ubyte * allowable_digest_len)]

            aggregated_measurement = cfm_aggregated_measurement_element(
                measurements_mask_arr,
                pmr_id,
                hash_type,
                len(allowable_digest_list),
                0,
                allowable_digest_buf
            )
            aggregated_measurement_len = ctypes.sizeof(aggregated_measurement)

            # Create TOC entry for aggregated measurements
            aggregated_toc_entry = manifest_common.manifest_toc_entry(
                manifest_common.CFM_V2_AGGREGATED_MEASUREMENT_TYPE_ID,
                manifest_common.CFM_V2_COMPONENT_DEVICE_TYPE_ID, 0, 0, 0,
                aggregated_measurement_len)

            aggregated_list.append((aggregated_measurement, aggregated_toc_entry))

    return aggregated_list

def generate_measurements (xml_measurements, measurement_hash_type):
    """
    Create a buffer of measurements section struct instances from parsed XML list

    :param xml_measurements: List of parsed XML of measurements to be included in CFM
    :param measurement_hash_type: Default hash type for measurement digests (component-level)

    :return List of (Measurement element, ToC entry) tuples
    """

    measurements_list = []

    for pmr_id, measurement_entries_dict in xml_measurements.items ():
        for measurement_id, version_sets in measurement_entries_dict.items ():
            allowable_digest_list = []
            allowable_digest_len = 0
            entries = 0
            for version_set, measurements_dict in version_sets["version_set"].items ():
                # Determine hash type for this version set: component default or per-measurement override
                if "hash_type" not in measurements_dict:
                    raise KeyError (
                        "Version set {0} for PMR {1} measurement {2} is missing required 'hash_type'".format (
                            version_set, pmr_id, measurement_id))
                vs_hash_type = measurements_dict["hash_type"]
                digest_len = manifest_common.get_hash_len (vs_hash_type)

                num_digests = len (measurements_dict["allowable_digests"])
                digests_buf = (ctypes.c_ubyte * (digest_len * num_digests)) ()
                digests_len = 0
                entries += 1
                for digest in measurements_dict["allowable_digests"]:
                    if len (digest) != digest_len:
                        raise ValueError ("Hash of type '{0}' has unexpected length {1} vs {2}".format (
                            vs_hash_type, len (digest), digest_len))

                    digest_arr = (ctypes.c_ubyte * digest_len).from_buffer_copy (digest)
                    ctypes.memmove (ctypes.addressof (digests_buf) + digests_len, digest_arr,
                        digest_len)
                    digests_len += digest_len

                # Encode hash type override: flag + manifest_hash_type value
                hash_type_override = 0 if vs_hash_type == measurement_hash_type else 1
                hash_type_field = vs_hash_type if hash_type_override else 0

                class cfm_allowable_digest_element (ctypes.LittleEndianStructure):
                    _pack_ = 1
                    _fields_ = [('version_set', ctypes.c_uint16),
                                ('digest_count', ctypes.c_ubyte),
                                ('hash_type_override', ctypes.c_ubyte, 1),
                                ('hash_type', ctypes.c_ubyte, 7),
                                ('digest', ctypes.c_ubyte * digests_len)]

                allowable_digest = cfm_allowable_digest_element (version_set, num_digests,
                    hash_type_override, hash_type_field, digests_buf)
                allowable_digest_list.append (allowable_digest)
                allowable_digest_len += ctypes.sizeof (allowable_digest)

            allowable_digest_buf = (ctypes.c_ubyte * allowable_digest_len) ()
            manifest_common.move_list_to_buffer (allowable_digest_buf, 0, allowable_digest_list)

            class cfm_measurement_element (ctypes.LittleEndianStructure):
                _pack_ = 1
                _fields_ = [('pmr_id', ctypes.c_ubyte),
                            ('measurement_id', ctypes.c_ubyte),
                            ('digest_count', ctypes.c_ubyte),
                            ('reserved', ctypes.c_ubyte),
                            ('digests_list', ctypes.c_ubyte * allowable_digest_len)]

            measurement = cfm_measurement_element (pmr_id, measurement_id, entries, 0,
                allowable_digest_buf)
            measurement_len = ctypes.sizeof (measurement)

            measurement_toc_entry = manifest_common.manifest_toc_entry (
                manifest_common.CFM_V2_MEASUREMENT_TYPE_ID,
                manifest_common.CFM_V2_COMPONENT_DEVICE_TYPE_ID, 0, 0, 0, measurement_len)

            measurements_list.append ((measurement, measurement_toc_entry))

    return measurements_list

def generate_measurement_data (xml_measurement_data):
    """
    Create a buffer of measurement data section struct instances from parsed XML list

    :param xml_measurement_data: List of parsed XML of measurement data to be included in CFM

    :return List of (Measurement data element, ToC entry) tuples
    """

    measurement_data_list = []

    for pmr_id, pmr_entries_dict in xml_measurement_data.items ():
        for measurement_id, measurement_data_dict in pmr_entries_dict.items ():
            allowable_data_list = []
            allowable_data_len = 0
            for group in measurement_data_dict["allowable_data"]:
                num_data = 0
                total_data_len = 0
                data_list = []
                data_list_buf = []
                for version_set, data_entries in group["data"]["version_set"].items ():
                    for data in data_entries:
                        num_data += 1
                        data_len = len (data)
                        manifest_common.check_maximum (data_len, 255,
                            "PMR {0} measurement {1} data length".format (pmr_id, measurement_id))
                        data_padding, data_padding_len = manifest_common.generate_4byte_padding_buf (
                            data_len)

                        data_buf = (ctypes.c_ubyte * data_len).from_buffer_copy (data)
                        data_buf_len = ctypes.sizeof (data_buf)

                        class cfm_allowable_data_element_entry (ctypes.LittleEndianStructure):
                            _pack_ = 1
                            _fields_ = [('version_set', ctypes.c_uint16),
                                        ('data_length', ctypes.c_uint16),
                                        ('data', ctypes.c_ubyte * data_buf_len),
                                        ('data_padding', ctypes.c_ubyte * data_padding_len)]

                        data_entry = cfm_allowable_data_element_entry (version_set, data_len, data_buf, data_padding)
                        data_list.append (data_entry)
                        total_data_len += ctypes.sizeof (data_entry)

                check = manifest_common.get_key_from_dict (group, "check", "Measurement Data")

                endianness = manifest_common.get_key_from_dict (group, "endianness",
                    "Measurement Data")

                data_list_buf = (ctypes.c_ubyte * total_data_len) ()
                manifest_common.move_list_to_buffer (data_list_buf, 0, data_list)

                if "bitmask" in group:
                    bitmask_len = group["bitmask_length"]
                    bitmask_padding, bitmask_padding_len = \
                        manifest_common.generate_4byte_padding_buf (bitmask_len)

                    bitmask_arr = (ctypes.c_ubyte * bitmask_len).from_buffer_copy (group["bitmask"])

                    class cfm_allowable_data_element (ctypes.LittleEndianStructure):
                        _pack_ = 1
                        _fields_ = [('check', ctypes.c_uint8, 3),
                                    ('reserved', ctypes.c_uint8, 4),
                                    ('endianness', ctypes.c_uint8, 1),
                                    ('num_data', ctypes.c_uint8),
                                    ('bitmask_length', ctypes.c_uint16),
                                    ('data_bitmask', ctypes.c_ubyte * bitmask_len),
                                    ('data_bitmask_padding', ctypes.c_ubyte * bitmask_padding_len),
                                    ('data', ctypes.c_ubyte * total_data_len)]

                    allowable_data = cfm_allowable_data_element (check, 0, endianness, num_data,
                        bitmask_len, bitmask_arr, bitmask_padding, data_list_buf)
                else:
                    class cfm_allowable_data_element (ctypes.LittleEndianStructure):
                        _pack_ = 1
                        _fields_ = [('check', ctypes.c_uint8, 3),
                                    ('reserved', ctypes.c_uint8, 4),
                                    ('endianness', ctypes.c_uint8, 1),
                                    ('num_data', ctypes.c_uint8),
                                    ('bitmask_length', ctypes.c_uint16),
                                    ('data', ctypes.c_ubyte * total_data_len)]

                    allowable_data = cfm_allowable_data_element (check, 0, endianness, num_data, 0,
                        data_list_buf)

                allowable_data_len = ctypes.sizeof (allowable_data)

                allowable_data_toc_entry = manifest_common.manifest_toc_entry (
                    manifest_common.CFM_V2_ALLOWABLE_DATA_TYPE_ID,
                    manifest_common.CFM_V2_MEASUREMENT_DATA_TYPE_ID, 0, 0, 0, allowable_data_len)

                allowable_data_list.append ((allowable_data, allowable_data_toc_entry))

            class cfm_measurement_data_element (ctypes.LittleEndianStructure):
                _pack_ = 1
                _fields_ = [('pmr_id', ctypes.c_ubyte),
                            ('measurement_id', ctypes.c_ubyte),
                            ('reserved', ctypes.c_uint16)]

            measurement_data = cfm_measurement_data_element (pmr_id, measurement_id, 0)
            measurement_data_len = ctypes.sizeof (measurement_data)

            measurement_data_toc_entry = manifest_common.manifest_toc_entry (
                manifest_common.CFM_V2_MEASUREMENT_DATA_TYPE_ID,
                manifest_common.CFM_V2_COMPONENT_DEVICE_TYPE_ID, 0, 0, 0, measurement_data_len)
            
            measurement_data_list.append ((measurement_data, measurement_data_toc_entry))
            measurement_data_list.extend (allowable_data_list)

    return measurement_data_list

def generate_allowable_manifest (xml_list, index, manifest_type, manifest_toc_type):
    """
    Create a buffer of allowable manifests from parsed XML list

    :param xml_list: List of parsed XML of allowable manifest to be included
    :param index: Manifest index. 0 if not applicable for manifest type
    :param manifest_type: Allowable manifest element type string
    :param manifest_toc_type: Allowable manifest element TOC type ID

    :return List of (Allowable manifest id element, ToC entry) tuples
    """

    allowable_manifest_list = []

    for manifest_id in xml_list["manifest_id"]:
        ids = []
        num_id = len (manifest_id["ids"])
        check = manifest_common.get_key_from_dict (manifest_id, "check",
            "Allowable {0}".format (manifest_type))

        endianness = manifest_common.get_key_from_dict (manifest_id, "endianness",
            "Measurement Data")

        for id in manifest_id["ids"]:
            ids.append (ctypes.c_uint32 (id))

        ids_buf = (ctypes.c_uint32 * num_id) ()
        manifest_common.move_list_to_buffer (ids_buf, 0, ids)

        class cfm_allowable_id_element (ctypes.LittleEndianStructure):
            _pack_ = 1
            _fields_ = [('check', ctypes.c_uint8, 3),
                        ('reserved', ctypes.c_uint8, 4),
                        ('endianness', ctypes.c_uint8, 1),
                        ('num_id', ctypes.c_uint8),
                        ('reserved', ctypes.c_uint16),
                        ('ids', ctypes.c_uint32 * num_id)]

        curr_manifest_id = cfm_allowable_id_element (check, 0, endianness, num_id, 0, ids_buf)

        curr_manifest_id_len = ctypes.sizeof (curr_manifest_id)
        curr_manifest_id_toc_entry = manifest_common.manifest_toc_entry (
            manifest_common.CFM_V2_ALLOWABLE_ID_TYPE_ID, manifest_toc_type, 0, 0, 0,
            curr_manifest_id_len)
        
        allowable_manifest_list.append ((curr_manifest_id, curr_manifest_id_toc_entry))

    platform_len = len (xml_list["platform"])

    manifest_common.check_maximum (platform_len, 255,
        "{0} platform {1} length".format (manifest_type, xml_list["platform"]))
    padding, padding_len = manifest_common.generate_4byte_padding_buf (platform_len)

    class cfm_allowable_manifest (ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('manifest_index', ctypes.c_ubyte),
                    ('platform_id_len', ctypes.c_ubyte),
                    ('platform_id', ctypes.c_char * platform_len),
                    ('platform_padding', ctypes.c_ubyte * padding_len)]

    allowable_manifest = cfm_allowable_manifest (index, platform_len,
        xml_list["platform"].encode ('utf-8'), padding)
    allowable_manifest_len = ctypes.sizeof (allowable_manifest)
    allowable_manifest_toc_entry = manifest_common.manifest_toc_entry (manifest_toc_type,
        manifest_common.CFM_V2_COMPONENT_DEVICE_TYPE_ID, 0, 0, 0, allowable_manifest_len)

    allowable_manifest_list.insert(0, (allowable_manifest, allowable_manifest_toc_entry))

    return allowable_manifest_list

def generate_allowable_pfm (xml_list):
    """
    Create a list of allowable PFM buffers from parsed XML list

    :param xml_list: List of parsed XML of allowable PFMs to be included in the CFM

    :return List of (Allowable PFM element, ToC entry) tuples
    """

    allowable_pfm_list = []

    for port_id, pfm_dict in xml_list.items ():
        allowable_pfm = generate_allowable_manifest (pfm_dict, port_id, "PFM",
                manifest_common.CFM_V2_ALLOWABLE_PFM_TYPE_ID)
        allowable_pfm_list.extend (allowable_pfm)

    return allowable_pfm_list

def generate_allowable_cfm (xml_list):
    """
    Create a list of allowable CFM buffers from parsed XML list

    :param xml_list: List of parsed XML of allowable CFMs to be included in the CFM

    :return List of (Allowable CFM element, ToC entry) tuples
    """

    allowable_cfm_list = []

    for index, cfm_dict in xml_list.items ():
        allowable_cfm = generate_allowable_manifest (cfm_dict, index, "CFM",
                manifest_common.CFM_V2_ALLOWABLE_CFM_TYPE_ID)
        
        allowable_cfm_list.extend (allowable_cfm)

    return allowable_cfm_list

def generate_allowable_pcd (xml_list):
    """
    Create a allowable PCD buffer from parsed XML list

    :param xml_list: List of parsed XML of allowable PCD to be included in the CFM

    :return Allowable PCD, allowable PCD TOC entry
    """

    return generate_allowable_manifest (xml_list, 0, "PCD",
            manifest_common.CFM_V2_ALLOWABLE_PCD_TYPE_ID)


def generate_comp_device (comp_device_type, num_pmr_digests, num_measurement, num_measurement_data,
    num_allowable_pfm, num_allowable_cfm, num_allowable_pcd, cert_slot, attestation_protocol,
    transcript_hash_type, measurement_hash_type, component_map, component_map_file):
    """
    Create a component device object from parsed XML list

    :param comp_device_type: Component device type string
    :param num_pmr_digests: Number of PMR digest objects for this component device
    :param num_measurement: Number of measurement objects for this component device
    :param num_measurement_data: Number of measurement data objects for this component device
    :param num_allowable_pfm: Number of allowable PFM objects for this component device
    :param num_allowable_cfm: Number of allowable CFM objects for this component device
    :param num_allowable_pcd: Number of allowable PCD objects for this component device
    :param cert_slot: The certificate slot to utilize during attestation for this component device
    :param attestation_protocol: The attestation protocol this component device supports
    :param transcript_hash_type: Hash type used for SPDM transcript hashing.
    :param measurement_hash_type: Hash type used to generate measurement, PMR, and root CA digests.
    :param component_map: Component type to ID map
    :param component_map_file: Component map file

    :return Instance of a comp_device object, comp_device's TOC entry
    """

    if (num_pmr_digests + num_measurement + num_measurement_data + num_allowable_pfm + \
        num_allowable_cfm + num_allowable_pcd) == 0:
        raise ValueError (
            "Component '{0}' has no PMR digests, measurement, measurement data or manifest ID tags".format (
                comp_device_type))

    component_id = component_map.get (comp_device_type)
    if component_id is None:
        component_id = manifest_common.add_component_mapping (comp_device_type,
            component_map_file)

    class cfm_comp_device_element (ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('cert_slot', ctypes.c_ubyte),
                    ('attestation_protocol', ctypes.c_ubyte),
                    ('transcript_hash_type', ctypes.c_ubyte, 3),
                    ('measurement_hash_type', ctypes.c_ubyte, 3),
                    ('reserved', ctypes.c_ubyte, 2),
                    ('reserved2', ctypes.c_ubyte),
                    ('component_id', ctypes.c_int32)]

    comp_device = cfm_comp_device_element (cert_slot, attestation_protocol, transcript_hash_type,
        measurement_hash_type, 0, 0, int (component_id))
    comp_device_len = ctypes.sizeof (comp_device)

    comp_device_toc_entry = manifest_common.manifest_toc_entry (
        manifest_common.CFM_V2_COMPONENT_DEVICE_TYPE_ID, manifest_common.V2_BASE_TYPE_ID, 0, 0, 0,
        comp_device_len)

    return (comp_device, comp_device_toc_entry)

def group_measurements_into_version_sets (xml_parsed_dict, component_key, components, version_number):
    """
    groups the measurements allowable digests into version sets. Version sets correspond to component 
    version numbers (Ver1 -> Version Set 1, Ver2 -> Version Set 2, etc.). When all versions have 
    identical hashes for a measurement, they are consolidated into Version Set 0.

    :param xml_parsed_dict: the dictionary that is created by load_xmls function by parsing the
                           xml files
    :param component_key: type string - The platform for component attesatation
    :param components: dictionary updated with version_set grouping, with old entries
    :param version_number: The version number of this component (1, 2, 3, etc.)

    :return components dictionary updated with version_set grouping, with new entries
    """

    if not "measurements" in components[component_key]:
        components[component_key]["measurements"] = {}

    for pmr_id, pmr_entries in xml_parsed_dict["measurements"].items ():
        if not pmr_id in components[component_key]["measurements"]:
            components[component_key]["measurements"][pmr_id] = {}

        for measurement_id, measurement_entries in pmr_entries.items ():
            if not (1 <= measurement_id <= 255):
                raise ValueError("Component '{0}', PMR {1}: measurement_id {2} is out of valid "
                    "range (1-255); ID 0 is reserved by SPDM (requests total "
                    "measurement count).".format(component_key, pmr_id, measurement_id))
            if measurement_id not in components[component_key]["measurements"].get(pmr_id, {}):
                # Initialize measurement_id entry if it doesn't exist
                components[component_key]["measurements"][pmr_id][measurement_id] = {"version_set": {}}
            # Add this version's measurement and hash_type to its corresponding version set
            vs_entry = dict(measurement_entries)
            vs_entry["hash_type"] = xml_parsed_dict["measurement_hash_type"]
            components[component_key]["measurements"][pmr_id][measurement_id]["version_set"][version_number] = vs_entry

    return components

def consolidate_identical_measurements(components, component_version_tracker):
    """
    After all versions are processed, consolidate measurements that have identical hashes 
    across all versions of EACH COMPONENT into Version Set 0, and remove the individual version sets.
    This is done per component, not globally.
    """
    for component_key, component_data in components.items():
        if "measurements" not in component_data:
            continue
            
        for pmr_id, pmr_data in component_data["measurements"].items():
            for measurement_id, measurement_data in pmr_data.items():
                version_sets = measurement_data["version_set"]
                
                if len(version_sets) <= 1:
                    continue  # Skip if only one version or no versions

                # If the number of version sets for this measurement doesn't match the
                # number of component versions processed, skip consolidation.
                comp_ver_count = component_version_tracker.get(component_key)
                if comp_ver_count is not None and len(version_sets) != comp_ver_count:
                    continue

                # Get all digests from all version sets for this component
                all_digests = []
                version_set_keys = list(version_sets.keys())
                
                for version_set_key in version_set_keys:
                    version_digests = set(version_sets[version_set_key]["allowable_digests"])
                    all_digests.append(version_digests)
                
                # Check if all versions of this component have identical digests
                if len(all_digests) > 1 and all(all_digests[0] == digest_set for digest_set in all_digests):
                    # All versions of this component have identical digests - consolidate to version set 0
                    first_version_set_key = version_set_keys[0]
                    consolidated_entry = version_sets[first_version_set_key].copy()
                    
                    # Clear all version sets and add consolidated entry as version set 0
                    version_sets.clear()
                    version_sets[0] = consolidated_entry
    
    return components

def consolidate_identical_measurement_data(components, component_version_tracker):
    """
    After all versions are processed, consolidate measurement data that have identical data 
    and check types across all versions of EACH COMPONENT into Version Set 0, and remove
    the individual version sets. This is done per component, not globally.
    Note: Data elements with different check types are kept separate.
    """
    for component_key, component_data in components.items():
        if "measurement_data" not in component_data:
            continue
            
        for pmr_id, pmr_data in component_data["measurement_data"].items():
            for measurement_id, measurement_data in pmr_data.items():
                allowable_data_list = measurement_data["allowable_data"]
                
                if not allowable_data_list:
                    continue

                # Build the set of all observed version_set identifiers for this measurement
                total_versions = set()
                for de in allowable_data_list:
                    if "data" in de and "version_set" in de["data"]:
                        total_versions.update(de["data"]["version_set"].keys())

                # Process each allowable data element
                for data_element in allowable_data_list:
                    if "data" not in data_element or "version_set" not in data_element["data"]:
                        continue
                        
                    version_sets = data_element["data"]["version_set"]
                    
                    if len(version_sets) <= 1:
                        continue  # Skip if only one version or no versions

                    # If the number of version sets for this data element doesn't match the
                    # number of component versions processed, skip consolidation.
                    comp_ver_count = component_version_tracker.get(component_key)
                    if comp_ver_count is not None and len(version_sets) != comp_ver_count:
                        continue

                    # Only consider consolidation to version_set 0 if this element actually covers
                    # all observed versions for this measurement. This avoids collapsing entries
                    # when other AllowableData elements exist for other checks/versions.
                    version_keys_set = set(version_sets.keys())
                    if version_keys_set != total_versions:
                        continue

                    # Get all data from all version sets for this component
                    all_data_sets = []
                    version_set_keys = list(version_sets.keys())
                    
                    for version_set_key in version_set_keys:
                        version_data = set(version_sets[version_set_key])
                        all_data_sets.append(version_data)
                    
                    # Check if all versions of this component have identical data
                    # Only consolidate if check types are already the same (handled by grouping function)
                    if len(all_data_sets) > 1 and all(all_data_sets[0] == data_set for data_set in all_data_sets):
                        # All versions of this component have identical data - consolidate to version set 0
                        first_version_set_key = version_set_keys[0]
                        consolidated_data = version_sets[first_version_set_key].copy()
                        
                        # Clear all version sets and add consolidated data as version set 0
                        version_sets.clear()
                        version_sets[0] = consolidated_data
    
    return components

def set_data_list_in_version_set_dict (allowable_data_list, version_set_num):
    """
    This is a helper function for group_measurement_data_into_version_sets function to group
    allowable data list into version set dictionary which will be processed by generate_measurement_data
    function

    :param allowable_data_list: allowable_data element list that is extracted from measurement_data dictionary
    :param version_set_num: integer value to group the data_list from the allowable_data element as version_set

    :return data_list: the data list is created with each data element with version set grouping
    """

    data_list = []
    for allowable_data_element in allowable_data_list:
        data_element = {}

        for data_key, data_value in allowable_data_element.items ():
            if data_key == "data":
                data_element[data_key] = {"version_set": {version_set_num:data_value}}
            else:
                data_element[data_key] = data_value

        data_list.append (data_element)

    return data_list

def group_measurement_data_into_version_sets (component_dict, component_key, components, version_number):
    """
    groups the measurement_data allowable_data into version sets using version numbers.
    If check types differ between versions, separate allowable_data elements are created.

    :param component_dict: the dictionary that is created by load_xmls function by parsing the
                           xml files
    :param component_key: type string - The platform for component attesatation
    :param components: dictionary updated with version_set grouping, with old entries
    :param version_number: The version number of this component (1, 2, 3, etc.)

    :return components dictionary updated with version_set grouping, with new entries
    """

    if not "measurement_data" in components[component_key]:
        components[component_key]["measurement_data"] = {}

    for pmr_id, pmr_entries in component_dict["measurement_data"].items ():
        if not pmr_id in components[component_key]["measurement_data"]:
            components[component_key]["measurement_data"][pmr_id] = {}

        for measurement_id, measurement_entries in pmr_entries.items ():
            if measurement_id not in components[component_key]["measurement_data"].get(pmr_id, {}):
                # Initialize measurement_id entry if it doesn't exist
                components[component_key]["measurement_data"][pmr_id][measurement_id] = {"allowable_data": []}

            data_list_to_append = set_data_list_in_version_set_dict (measurement_entries["allowable_data"], version_number)
            # Merge with existing data or add new data for this version
            if not components[component_key]["measurement_data"][pmr_id][measurement_id]["allowable_data"]:
                components[component_key]["measurement_data"][pmr_id][measurement_id]["allowable_data"] = data_list_to_append
            else:
                # Add this version's data to existing structure
                for new_data_element in data_list_to_append:
                    # Find matching existing element based on check type, bitmask, and endianness
                    matching_element_found = False

                    for existing_element in components[component_key]["measurement_data"][pmr_id][measurement_id]["allowable_data"]:
                        # Check if all attributes match (check, endianness, bitmask)
                        if (existing_element.get("check") == new_data_element.get("check") and
                            existing_element.get("bitmask") == new_data_element.get("bitmask") and
                            existing_element.get("endianness") == new_data_element.get("endianness")):
                            # Matching element found - merge version sets
                            existing_element["data"]["version_set"].update(new_data_element["data"]["version_set"])
                            matching_element_found = True
                            break

                    if not matching_element_found:
                        # No matching element found - add as new allowable_data element
                        components[component_key]["measurement_data"][pmr_id][measurement_id]["allowable_data"].append(new_data_element)

    return components

#*************************************** Start of Script ***************************************

def main(argv=None):
    """
    Usage:
        python3 cfm_generator.py [path/to/cfm_generator.config]

    Required input:
        A generator configuration file that points to one or more CFM XML inputs and output
        settings. If no argument is provided, the local default cfm_generator.config in this
        directory is used.
    """
    default_config = os.path.join (os.path.dirname (os.path.abspath (__file__)), CFM_CONFIG_FILENAME)
    parser = argparse.ArgumentParser (description = 'Create a CFM')
    parser.add_argument ('config', nargs = '?', default = default_config,
        help = 'Path to configuration file')
    parser.add_argument('-n', '--no-aggregation', action='store_true',
        help='Disable measurement aggregation - generate all measurements as regular (non-aggregated)')
    args = parser.parse_args (argv)
    no_aggregation = args.no_aggregation

    processed_xml, sign, key_size, key, key_type, hash_type, cfm_id, output, xml_version, empty, \
        max_num_rw_sections, selection_list, component_map, component_map_file = \
            manifest_common.load_xmls (args.config, None, manifest_types.CFM)

    hash_engine = manifest_common.get_hash_engine (hash_type)
    platform_id = selection_list["platform_id"]

    components = {}
    elements_list = []

    # Track version numbers per component
    component_version_tracker = {}

    for xml_key, xml_dict in processed_xml.items ():
        for component_key, component_dict in xml_dict.items ():
            # Get the next version number for this specific component
            if component_key not in component_version_tracker:
                component_version_tracker[component_key] = 1
            else:
                component_version_tracker[component_key] += 1
            
            component_version_number = component_version_tracker[component_key]
            
            if component_key in components:
                if "root_ca_digests" in component_dict:
                    for digest in component_dict["root_ca_digests"]["allowable_digests"]:
                        if not digest in components[component_key]["root_ca_digests"]["allowable_digests"]:
                            components[component_key]["root_ca_digests"]["allowable_digests"].append (digest)

                if "measurements" in component_dict:
                    components = group_measurements_into_version_sets (component_dict, component_key, components, component_version_number)

                if "measurement_data" in component_dict:
                    components = group_measurement_data_into_version_sets (component_dict, component_key, \
                        components, component_version_number)

            else:
                components.update ({component_key:{}})

                for element_key, element_dict in component_dict.items ():
                    if not element_key in ["measurements", "measurement_data"]:
                        components[component_key][element_key] = element_dict
                        continue

                    if element_key == "measurements":
                        components[component_key][element_key] = {}

                        for pmr_id, pmr_entries in element_dict.items ():
                            components[component_key][element_key][pmr_id] = {}

                            for measurement_id, measurement_entries in pmr_entries.items ():
                                vs_entry = dict (measurement_entries)
                                vs_entry["hash_type"] = component_dict["measurement_hash_type"]
                                components[component_key][element_key][pmr_id][measurement_id] = {"version_set":{}}
                                components[component_key][element_key][pmr_id][measurement_id]["version_set"][component_version_number] = vs_entry

                    if element_key == "measurement_data":
                        components[component_key][element_key] = {}

                        for pmr_id, pmr_entries in element_dict.items ():
                            components[component_key][element_key][pmr_id] = {}

                            for measurement_id, measurement_entries in pmr_entries.items ():
                                data_list_to_append = set_data_list_in_version_set_dict (measurement_entries["allowable_data"], component_version_number)
                                components[component_key][element_key][pmr_id][measurement_id] = \
                                    {"allowable_data" : data_list_to_append}

    # After processing all XML files, consolidate identical measurements into Version Set 0
    components = consolidate_identical_measurements(components, component_version_tracker)

    # After processing all XML files, consolidate identical measurement data into Version Set 0
    components = consolidate_identical_measurement_data(components, component_version_tracker)

    platform_id = manifest_common.generate_platform_id ({"platform_id": platform_id})
    elements_list.append (platform_id)

    if not empty:
        for component_type, component_dict in components.items ():
            num_pmr_digests = 0
            num_measurements = 0
            num_measurement_data = 0
            num_allowable_pfm = 0
            num_allowable_cfm = 0
            num_allowable_pcd = 0

            component_elements_list = []

            if "root_ca_digests" in component_dict:
                root_ca_digests = generate_root_ca_digests (component_dict["root_ca_digests"],
                        component_dict["measurement_hash_type"])

                component_elements_list.append (root_ca_digests)

            if "pmr" in component_dict:
                pmr = generate_pmr (component_dict["pmr"],
                    component_dict["measurement_hash_type"])

                component_elements_list.extend (pmr)

            if "pmr_digests" in component_dict:
                pmr_digests = generate_pmr_digests (component_dict["pmr_digests"],
                        component_dict["measurement_hash_type"])

                component_elements_list.extend (pmr_digests)
                num_pmr_digests = len(pmr_digests)

            if (component_dict["unique"] == 0) and ("measurements" in component_dict):
                if no_aggregation or xml_version in (
                    manifest_types.VERSION_1,
                    manifest_types.VERSION_2,
                ):
                    measurements = generate_measurements (component_dict["measurements"],
                            component_dict["measurement_hash_type"])

                    component_elements_list.extend (measurements)
                    num_measurements += len(measurements)
                else:
                    # Analyze and separate measurements into aggregatable and regular
                    aggregated_measurements_data, regular_measurements_data = \
                        analyze_measurements_for_aggregation(component_dict["measurements"],
                                                            component_dict["unique"])

                    # Generate regular measurements if any exist
                    if regular_measurements_data:
                        measurements = generate_measurements(regular_measurements_data,
                                component_dict["measurement_hash_type"])

                        component_elements_list.extend (measurements)
                        num_measurements += len(measurements)

                    # Generate aggregated measurements if any exist
                    if aggregated_measurements_data:
                        measurements = generate_aggregated_measurements(
                                aggregated_measurements_data, hash_type,
                                component_dict["measurement_hash_type"])

                        component_elements_list.extend (measurements)
                        num_measurements += len(measurements)

            if "measurement_data" in component_dict:
                measurement_data = generate_measurement_data (
                        component_dict["measurement_data"])

                component_elements_list.extend (measurement_data)
                num_measurement_data = len(measurement_data)

            if (component_dict["unique"] == 1) and ("measurements" in component_dict):
                if no_aggregation or xml_version in (
                    manifest_types.VERSION_1,
                    manifest_types.VERSION_2,
                ):
                    measurements = generate_measurements (component_dict["measurements"],
                            component_dict["measurement_hash_type"])

                    component_elements_list.extend (measurements)
                    num_measurements += len(measurements)
                else:
                    # Analyze and separate measurements into aggregatable and regular
                    aggregated_measurements_data, regular_measurements_data = \
                        analyze_measurements_for_aggregation(component_dict["measurements"],
                                                            component_dict["unique"])

                    # Generate regular measurements if any exist
                    if regular_measurements_data:
                        measurements = generate_measurements(regular_measurements_data,
                                component_dict["measurement_hash_type"])

                        component_elements_list.extend (measurements)
                        num_measurements += len(measurements)

                    # Generate aggregated measurements if any exist
                    if aggregated_measurements_data:
                        measurements = generate_aggregated_measurements(
                                aggregated_measurements_data, hash_type,
                                component_dict["measurement_hash_type"])

                        component_elements_list.extend (measurements)
                        num_measurements += len(measurements)

            if "allowable_pfm" in component_dict:
                allowable_pfm = generate_allowable_pfm (component_dict["allowable_pfm"])

                component_elements_list.extend (allowable_pfm)
                num_allowable_pfm = len(allowable_pfm)

            if "allowable_cfm" in component_dict:
                allowable_cfm = generate_allowable_cfm (component_dict["allowable_cfm"])

                component_elements_list.extend (allowable_cfm)
                num_allowable_cfm = len(allowable_cfm)

            if "allowable_pcd" in component_dict:
                allowable_pcd = generate_allowable_pcd (component_dict["allowable_pcd"])
                component_elements_list.extend (allowable_pcd)
                num_allowable_pcd = 1

            comp_device = generate_comp_device (component_type,
                num_pmr_digests, num_measurements, num_measurement_data, num_allowable_pfm,
                num_allowable_cfm, num_allowable_pcd, component_dict["slot_num"],
                component_dict["attestation_protocol"],
                component_dict["transcript_hash_type"], component_dict["measurement_hash_type"],
                component_map, component_map_file)

            elements_list.append (comp_device)
            elements_list.extend (component_elements_list)

    manifest_common.generate_manifest (hash_engine, hash_type, cfm_id, manifest_types.CFM, xml_version,
        sign, key, key_size, key_type, elements_list, output)

    print ("Completed CFM generation: {0}".format (output))


if __name__ == '__main__':
    main()
