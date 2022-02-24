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


def generate_root_ca_digests (xml_root_ca_digests, hash_engine):
    """
    Create a buffer of a Root CA digest struct instance from parsed XML list

    :param xml_root_ca_digests: List of parsed XML of root CA digests to be included in CFM
    :param hash_engine: Hashing engine

    :return Root CA digests buffer, Root CA digests TOC entry, Root CA digests hash
    """

    hash_type = manifest_common.get_key_from_dict (xml_root_ca_digests, "hash_type",
        "Root CA Digests")

    digest_len = manifest_common.get_hash_len (hash_type)
    num_digests = len (xml_root_ca_digests["allowable_digests"])
    digests_buf = (ctypes.c_ubyte * (digest_len * num_digests)) ()
    digests_len = 0

    for digest in xml_root_ca_digests["allowable_digests"]:
        if len (digest) != digest_len:
            raise ValueError ("Hash of type '{0}' has unexpected length {1} vs {2}".format (
                hash_type, len (digest), digest_len))

        digest_arr = (ctypes.c_ubyte * digest_len).from_buffer_copy (digest)
        ctypes.memmove (ctypes.addressof (digests_buf) + digests_len, digest_arr, digest_len)
        digests_len += digest_len

    class cfm_root_ca_digest_element (ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('reserved', ctypes.c_ubyte, 5),
                    ('hash_type', ctypes.c_ubyte, 3),
                    ('ca_count', ctypes.c_ubyte),
                    ('reserved2', ctypes.c_uint16),
                    ('digests', ctypes.c_ubyte * digests_len)]

    root_ca_digests = cfm_root_ca_digest_element (0, hash_type, num_digests, 0, digests_buf)
    root_ca_digests_len = ctypes.sizeof (root_ca_digests)

    root_ca_digests_toc_entry = manifest_common.manifest_toc_entry (
        manifest_common.CFM_V2_ROOT_CA_TYPE_ID,
        manifest_common.CFM_V2_COMPONENT_DEVICE_TYPE_ID, 0, 0, 0, root_ca_digests_len)

    root_ca_digests_hash = manifest_common.generate_hash (root_ca_digests, hash_engine)

    return root_ca_digests, root_ca_digests_toc_entry, root_ca_digests_hash

def generate_pmr (xml_pmr, hash_engine):
    """
    Create a buffer of PMR section struct instances from parsed XML list

    :param xml_pmr: List of parsed XML of PMRs to be included in CFM
    :param hash_engine: Hashing engine

    :return PMR buffer, list of PMR TOC entries, list of PMR hashes
    """

    pmrs_list = []
    pmrs_toc_list = []
    pmrs_hash_list = []
    pmrs_len = 0

    for pmr_id, pmr_dict in xml_pmr.items ():
        pmr_hash_type = manifest_common.get_key_from_dict (pmr_dict, "hash_type","PMR")

        digest_len = manifest_common.get_hash_len (pmr_hash_type)

        if len (pmr_dict["initial_value"]) != digest_len:
            raise ValueError ("Initial value of PMR '{0}' has unexpected length {1} vs {2}".format (
                pmr_id, len (pmr_dict["initial_value"]), digest_len))

        initial_value_arr = (ctypes.c_ubyte * digest_len).from_buffer_copy (
            pmr_dict["initial_value"])

        class cfm_pmr_element (ctypes.LittleEndianStructure):
            _pack_ = 1
            _fields_ = [('pmr_id', ctypes.c_ubyte),
                        ('reserved', ctypes.c_ubyte, 5),
                        ('hash_type', ctypes.c_ubyte, 3),
                        ('reserved2', ctypes.c_uint16),
                        ('initial_value', ctypes.c_ubyte * digest_len)]

        pmr = cfm_pmr_element (pmr_id, 0, pmr_hash_type, 0, initial_value_arr)
        pmr_len = ctypes.sizeof (pmr)

        pmr_toc_entry = manifest_common.manifest_toc_entry (
            manifest_common.CFM_V2_PMR_TYPE_ID, manifest_common.CFM_V2_COMPONENT_DEVICE_TYPE_ID, 0,
            0, 0, pmr_len)

        pmr_hash = manifest_common.generate_hash (pmr, hash_engine)

        pmrs_list.append (pmr)
        pmrs_toc_list.append (pmr_toc_entry)
        pmrs_hash_list.append (pmr_hash)

        pmrs_len += ctypes.sizeof (pmr)

    pmrs_buf = (ctypes.c_ubyte * pmrs_len) ()
    manifest_common.move_list_to_buffer (pmrs_buf, 0, pmrs_list)

    return pmrs_buf, pmrs_toc_list, pmrs_hash_list

def generate_pmr_digests (xml_pmr_digests, hash_engine):
    """
    Create a buffer of PMR digests section struct instances from parsed XML list

    :param xml_pmr_digests: List of parsed XML of PMR digests to be included in CFM
    :param hash_engine: Hashing engine

    :return PMR digests buffer, number of PMR digests, list of PMR digests TOC entries,
        list of PMR digests hashes
    """

    pmr_digests_list = []
    pmr_digests_toc_list = []
    pmr_digests_hash_list = []
    pmr_digests_len = 0

    for pmr_id, pmr_digest_dict in xml_pmr_digests.items ():
        pmr_hash_type = manifest_common.get_key_from_dict (pmr_digest_dict, "hash_type",
            "PMR Digests")

        digest_len = manifest_common.get_hash_len (pmr_hash_type)
        num_digests = len (pmr_digest_dict["allowable_digests"])
        digests_buf = (ctypes.c_ubyte * (digest_len * num_digests)) ()
        digests_len = 0

        for digest in pmr_digest_dict["allowable_digests"]:
            if len (digest) != digest_len:
                raise ValueError ("Hash of type '{0}' has unexpected length {1} vs {2}".format (
                    pmr_hash_type, len (digest), digest_len))

            digest_arr = (ctypes.c_ubyte * digest_len).from_buffer_copy (digest)
            ctypes.memmove (ctypes.addressof (digests_buf) + digests_len, digest_arr, digest_len)
            digests_len += digest_len

        class cfm_pmr_digest_element (ctypes.LittleEndianStructure):
            _pack_ = 1
            _fields_ = [('pmr_id', ctypes.c_ubyte),
                        ('reserved', ctypes.c_ubyte, 5),
                        ('pmr_hash_type', ctypes.c_ubyte, 3),
                        ('num_digests', ctypes.c_ubyte),
                        ('reserved2', ctypes.c_ubyte),
                        ('digests', ctypes.c_ubyte * digests_len)]

        pmr_digest = cfm_pmr_digest_element (pmr_id, 0, pmr_hash_type, num_digests, 0, digests_buf)
        pmr_digest_len = ctypes.sizeof (pmr_digest)

        pmr_digest_toc_entry = manifest_common.manifest_toc_entry (
            manifest_common.CFM_V2_PMR_DIGEST_TYPE_ID,
            manifest_common.CFM_V2_COMPONENT_DEVICE_TYPE_ID, 0, 0, 0, pmr_digest_len)

        pmr_digest_hash = manifest_common.generate_hash (pmr_digest, hash_engine)

        pmr_digests_list.append (pmr_digest)
        pmr_digests_toc_list.append (pmr_digest_toc_entry)
        pmr_digests_hash_list.append (pmr_digest_hash)

        pmr_digests_len += ctypes.sizeof (pmr_digest)

    pmr_digests_buf = (ctypes.c_ubyte * pmr_digests_len) ()
    manifest_common.move_list_to_buffer (pmr_digests_buf, 0, pmr_digests_list)

    return pmr_digests_buf, len (xml_pmr_digests), pmr_digests_toc_list, pmr_digests_hash_list

def generate_measurements (xml_measurements, hash_engine):
    """
    Create a buffer of measurements section struct instances from parsed XML list

    :param xml_measurements: List of parsed XML of measurements to be included in CFM
    :param hash_engine: Hashing engine

    :return measurements buffer, number of measurements, list of measurements TOC entries,
        list of measurements hashes
    """

    measurements_list = []
    measurements_toc_list = []
    measurements_hash_list = []
    measurements_len = 0

    for pmr_id, measurement_entries_dict in xml_measurements.items ():
        for measurement_id, measurements_dict in measurement_entries_dict.items ():
            measurements_hash_type = manifest_common.get_key_from_dict (measurements_dict,
                "hash_type", "Measurements")

            digest_len = manifest_common.get_hash_len (measurements_hash_type)
            num_digests = len (measurements_dict["allowable_digests"])
            digests_buf = (ctypes.c_ubyte * (digest_len * num_digests)) ()
            digests_len = 0

            for digest in measurements_dict["allowable_digests"]:
                if len (digest) != digest_len:
                    raise ValueError ("Hash of type '{0}' has unexpected length {1} vs {2}".format (
                        measurements_hash_type, len (digest), digest_len))

                digest_arr = (ctypes.c_ubyte * digest_len).from_buffer_copy (digest)
                ctypes.memmove (ctypes.addressof (digests_buf) + digests_len, digest_arr, digest_len)
                digests_len += digest_len

            class cfm_measurement_element (ctypes.LittleEndianStructure):
                _pack_ = 1
                _fields_ = [('pmr_id', ctypes.c_ubyte),
                            ('measurement_id', ctypes.c_ubyte),
                            ('reserved', ctypes.c_ubyte, 5),
                            ('measurement_hash_type', ctypes.c_ubyte, 3),
                            ('digest_count', ctypes.c_ubyte),
                            ('digests', ctypes.c_ubyte * digests_len)]

            measurement = cfm_measurement_element (pmr_id, measurement_id, 0,
                measurements_hash_type, num_digests, digests_buf)
            measurement_len = ctypes.sizeof (measurement)

            measurement_toc_entry = manifest_common.manifest_toc_entry (
                manifest_common.CFM_V2_MEASUREMENT_TYPE_ID,
                manifest_common.CFM_V2_COMPONENT_DEVICE_TYPE_ID, 0, 0, 0, measurement_len)

            measurement_hash = manifest_common.generate_hash (measurement, hash_engine)

            measurements_list.append (measurement)
            measurements_toc_list.append (measurement_toc_entry)
            measurements_hash_list.append (measurement_hash)

            measurements_len += ctypes.sizeof (measurement)

    measurements_buf = (ctypes.c_ubyte * measurements_len) ()
    manifest_common.move_list_to_buffer (measurements_buf, 0, measurements_list)

    return measurements_buf, len (measurements_hash_list), measurements_toc_list, \
        measurements_hash_list

def generate_measurement_data (xml_measurement_data, hash_engine):
    """
    Create a buffer of measurement data section struct instances from parsed XML list

    :param xml_measurement_data: List of parsed XML of measurement data to be included in CFM
    :param hash_engine: Hashing engine

    :return Measurement data buffer, number of measurement data, list of measurement data TOC
        entries, list of measurement data hashes
    """

    measurement_data_list = []
    measurement_data_toc_list = []
    measurement_data_hash_list = []
    measurement_data_buf_len = 0

    for pmr_id, pmr_entries_dict in xml_measurement_data.items ():
        for measurement_id, measurement_data_dict in pmr_entries_dict.items ():
            data_len = measurement_data_dict["data_len"]
            allowable_data_list = []
            allowable_data_toc_list = []
            allowable_data_hash_list = []
            allowable_data_len = 0

            for group in measurement_data_dict["allowable_data"]:
                manifest_common.check_maximum (data_len, 255,
                    "PMR {0} measurement {1} data length".format (pmr_id, measurement_id))
                num_data = len (group["data"])
                data_buf_len = num_data * data_len
                data_list = []

                for data in group["data"]:
                    data_list.append ((ctypes.c_ubyte * data_len).from_buffer_copy (data))

                data_buf = (ctypes.c_ubyte * data_buf_len) ()
                data_buf_len = manifest_common.move_list_to_buffer (data_buf, 0, data_list)
                data_padding, data_padding_len = manifest_common.generate_4byte_padding_buf (
                    data_buf_len)

                reserved_buf = (ctypes.c_ubyte * 3) ()
                ctypes.memset (reserved_buf, 0, ctypes.sizeof (ctypes.c_ubyte) * 3)

                check = manifest_common.get_key_from_dict (group, "check", "Measurement Data")

                if "bitmask" in group:
                    bitmask_len = data_len
                    bitmask_padding, bitmask_padding_len = \
                        manifest_common.generate_4byte_padding_buf (bitmask_len)

                    bitmask_arr = (ctypes.c_ubyte * bitmask_len).from_buffer_copy (group["bitmask"])

                    class cfm_allowable_data_element (ctypes.LittleEndianStructure):
                        _pack_ = 1
                        _fields_ = [('reserved', ctypes.c_uint8, 7),
                                    ('bitmask_presence', ctypes.c_uint8, 1),
                                    ('check', ctypes.c_uint8),
                                    ('num_data', ctypes.c_uint8),
                                    ('data_len', ctypes.c_uint16),
                                    ('reserved2', ctypes.c_ubyte * 3),
                                    ('data_bitmask', ctypes.c_ubyte * bitmask_len),
                                    ('data_bitmask_padding', ctypes.c_ubyte * bitmask_padding_len),
                                    ('data', ctypes.c_ubyte * data_buf_len),
                                    ('data_padding', ctypes.c_ubyte * data_padding_len)]

                    allowable_data = cfm_allowable_data_element (0, 1, check, num_data, data_len,
                        reserved_buf, bitmask_arr, bitmask_padding, data_buf, data_padding)
                else:
                    class cfm_allowable_data_element (ctypes.LittleEndianStructure):
                        _pack_ = 1
                        _fields_ = [('reserved', ctypes.c_uint8, 7),
                                    ('bitmask_presence', ctypes.c_uint8, 1),
                                    ('check', ctypes.c_uint8),
                                    ('num_data', ctypes.c_uint8),
                                    ('data_len', ctypes.c_uint16),
                                    ('reserved2', ctypes.c_ubyte * 3),
                                    ('data', ctypes.c_ubyte * data_buf_len),
                                    ('data_padding', ctypes.c_ubyte * data_padding_len)]

                    allowable_data = cfm_allowable_data_element (0, 0, check, num_data, data_len,
                        reserved_buf, data_buf, data_padding)

                allowable_data_len = ctypes.sizeof (allowable_data)
                measurement_data_buf_len += allowable_data_len
                allowable_data_list.append (allowable_data)

                allowable_data_toc_list.append (manifest_common.manifest_toc_entry (
                    manifest_common.CFM_V2_ALLOWABLE_DATA_TYPE_ID,
                    manifest_common.CFM_V2_MEASUREMENT_DATA_TYPE_ID, 0, 0, 0, allowable_data_len))
                allowable_data_hash_list.append (manifest_common.generate_hash (allowable_data,
                    hash_engine))

            class cfm_measurement_data_element (ctypes.LittleEndianStructure):
                _pack_ = 1
                _fields_ = [('pmr_id', ctypes.c_ubyte),
                            ('measurement_id', ctypes.c_ubyte),
                            ('reserved', ctypes.c_uint16)]

            measurement_data = cfm_measurement_data_element (pmr_id, measurement_id, 0)
            measurement_data_len = ctypes.sizeof (measurement_data)
            measurement_data_buf_len += measurement_data_len
            measurement_data_list.append (measurement_data)
            measurement_data_list.extend (allowable_data_list)

            measurement_data_toc_list.append (manifest_common.manifest_toc_entry (
                manifest_common.CFM_V2_MEASUREMENT_DATA_TYPE_ID,
                manifest_common.CFM_V2_COMPONENT_DEVICE_TYPE_ID, 0, 0, 0, measurement_data_len))
            measurement_data_toc_list.extend (allowable_data_toc_list)
            measurement_data_hash_list.append (manifest_common.generate_hash (measurement_data,
                hash_engine))
            measurement_data_hash_list.extend (allowable_data_hash_list)

    measurement_data_buf = (ctypes.c_ubyte * measurement_data_buf_len) ()
    manifest_common.move_list_to_buffer (measurement_data_buf, 0, measurement_data_list)

    return measurement_data_buf, len (measurement_data_list), measurement_data_toc_list, \
        measurement_data_hash_list

def generate_allowable_manifest (xml_list, hash_engine, index, manifest_type, manifest_toc_type):
    """
    Create a buffer of allowable manifests from parsed XML list

    :param xml_list: List of parsed XML of allowable manifest to be included
    :param hash_engine: Hashing engine
    :param index: Manifest index. 0 if not applicable for manifest type
    :param manifest_type: Allowable manifest element type string
    :param manifest_toc_type: Allowable manifest element TOC type ID

    :return Instance of a allowable_manifest object
    """

    allowable_manifest_list = []
    allowable_manifest_buf_len = 0
    manifest_id_toc_list = []
    manifest_id_hash_list = []

    for manifest_id in xml_list["manifest_id"]:
        ids = []
        num_id = len (manifest_id["ids"])
        check = manifest_common.get_key_from_dict (manifest_id, "check",
            "Allowable {0}".format (manifest_type))

        for id in manifest_id["ids"]:
            ids.append (ctypes.c_uint32 (id))

        ids_buf = (ctypes.c_uint32 * num_id) ()
        manifest_common.move_list_to_buffer (ids_buf, 0, ids)

        class cfm_allowable_id_element (ctypes.LittleEndianStructure):
            _pack_ = 1
            _fields_ = [('check', ctypes.c_uint8),
                        ('num_id', ctypes.c_uint8),
                        ('reserved', ctypes.c_uint16),
                        ('ids', ctypes.c_uint32 * num_id)]

        curr_manifest_id = cfm_allowable_id_element (check, num_id, 0, ids_buf)
        curr_manifest_id_len = ctypes.sizeof (curr_manifest_id)
        allowable_manifest_buf_len += curr_manifest_id_len
        allowable_manifest_list.append (curr_manifest_id)

        manifest_id_toc_list.append (manifest_common.manifest_toc_entry (
            manifest_common.CFM_V2_ALLOWABLE_ID_TYPE_ID, manifest_toc_type, 0, 0, 0,
            curr_manifest_id_len))
        manifest_id_hash_list.append (manifest_common.generate_hash (curr_manifest_id,
            hash_engine))

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
    allowable_manifest_buf_len += allowable_manifest_len
    allowable_manifest_list = [allowable_manifest] + allowable_manifest_list

    manifest_id_toc_list = [manifest_common.manifest_toc_entry (manifest_toc_type,
        manifest_common.CFM_V2_COMPONENT_DEVICE_TYPE_ID, 0, 0, 0, allowable_manifest_len)] + \
        manifest_id_toc_list
    manifest_id_hash_list = [manifest_common.generate_hash (allowable_manifest, hash_engine)] + \
        manifest_id_hash_list

    return allowable_manifest_list, allowable_manifest_buf_len, manifest_id_toc_list, \
        manifest_id_hash_list

def generate_allowable_pfm (xml_list, hash_engine):
    """
    Create a list of allowable PFM buffers from parsed XML list

    :param xml_list: List of parsed XML of allowable PFMs to be included in the CFM
    :param hash_engine: Hashing engine

    :return Allowable PFMs buffer, number of allowable PFMs, list of allowable PFM TOC entries, list
        of allowable PFM hashes
    """

    num_allowable_pfm = len (xml_list)
    allowable_pfm_buf_len = 0
    allowable_pfm_list = []
    allowable_pfm_toc_list = []
    allowable_pfm_hash_list = []

    for port_id, pfm_dict in xml_list.items ():
        allowable_pfm, allowable_pfm_len, allowable_pfm_toc, allowable_pfm_hashes = \
            generate_allowable_manifest (pfm_dict, hash_engine, port_id, "PFM",
                manifest_common.CFM_V2_ALLOWABLE_PFM_TYPE_ID)
        allowable_pfm_buf_len += allowable_pfm_len
        allowable_pfm_list.extend (allowable_pfm)

        allowable_pfm_toc_list.extend (allowable_pfm_toc)
        allowable_pfm_hash_list.extend (allowable_pfm_hashes)

    allowable_pfm_buf = (ctypes.c_ubyte * allowable_pfm_buf_len) ()
    allowable_pfm_buf_len = manifest_common.move_list_to_buffer (allowable_pfm_buf, 0,
        allowable_pfm_list)

    return allowable_pfm_buf, num_allowable_pfm, allowable_pfm_toc_list, allowable_pfm_hash_list

def generate_allowable_cfm (xml_list, hash_engine):
    """
    Create a list of allowable CFM buffers from parsed XML list

    :param xml_list: List of parsed XML of allowable CFMs to be included in the CFM
    :param hash_engine: Hashing engine

    :return Allowable CFMs buffer, number of allowable CFMs, list of allowable CFM TOC entries, list
        of allowable CFM hashes
    """

    num_allowable_cfm = len (xml_list)
    allowable_cfm_buf_len = 0
    allowable_cfm_list = []
    allowable_cfm_toc_list = []
    allowable_cfm_hash_list = []

    for index, cfm_dict in xml_list.items ():
        allowable_cfm, allowable_cfm_len, allowable_cfm_toc, allowable_cfm_hashes = \
            generate_allowable_manifest (cfm_dict, hash_engine, index, "CFM",
                manifest_common.CFM_V2_ALLOWABLE_CFM_TYPE_ID)
        allowable_cfm_buf_len += allowable_cfm_len
        allowable_cfm_list.extend (allowable_cfm)

        allowable_cfm_toc_list.extend (allowable_cfm_toc)
        allowable_cfm_hash_list.extend (allowable_cfm_hashes)

    allowable_cfm_buf = (ctypes.c_ubyte * allowable_cfm_buf_len) ()
    allowable_cfm_buf_len = manifest_common.move_list_to_buffer (allowable_cfm_buf, 0,
        allowable_cfm_list)

    return allowable_cfm_buf, num_allowable_cfm, allowable_cfm_toc_list, allowable_cfm_hash_list

def generate_allowable_pcd (xml_list, hash_engine):
    """
    Create a allowable PCD buffer from parsed XML list

    :param xml_list: List of parsed XML of allowable PCD to be included in the CFM
    :param hash_engine: Hashing engine

    :return Allowable PCD buffer, allowable PCD TOC entry, allowable PCD hash
    """

    allowable_pcd, allowable_pcd_len, allowable_pcd_toc, allowable_pcd_hash = \
        generate_allowable_manifest (xml_list, hash_engine, 0, "PCD",
            manifest_common.CFM_V2_ALLOWABLE_PCD_TYPE_ID)

    allowable_pcd_buf = (ctypes.c_ubyte * allowable_pcd_len) ()
    manifest_common.move_list_to_buffer (allowable_pcd_buf, 0, allowable_pcd)

    return allowable_pcd_buf, allowable_pcd_toc, allowable_pcd_hash

def generate_comp_device (comp_device_type, num_pmr_digests, num_measurement, num_measurement_data,
    num_allowable_pfm, num_allowable_cfm, num_allowable_pcd, cert_slot, attestation_protocol,
    hash_engine):
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
    :param hash_engine: Hashing engine

    :return Instance of a comp_device object, comp_device's TOC entry, hash of comp_device object
    """

    if (num_pmr_digests + num_measurement + num_measurement_data + num_allowable_pfm + \
        num_allowable_cfm + num_allowable_pcd) == 0:
        raise ValueError (
            "Component '{0}' has no PMR digests, measurement, measurement data or manifest ID tags".format (
                comp_device_type))

    type_len = len (comp_device_type)

    manifest_common.check_maximum (type_len, 255, "Component type {0} length".format (
        comp_device_type))
    padding, padding_len = manifest_common.generate_4byte_padding_buf (type_len)

    class cfm_comp_device_element (ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('cert_slot', ctypes.c_ubyte),
                    ('attestation_protocol', ctypes.c_ubyte),
                    ('reserved', ctypes.c_ubyte),
                    ('type_len', ctypes.c_ubyte),
                    ('type', ctypes.c_char * type_len),
                    ('type_padding', ctypes.c_ubyte * padding_len)]

    comp_device = cfm_comp_device_element (cert_slot, attestation_protocol, 0, type_len,
        comp_device_type.encode ('utf-8'), padding)
    comp_device_len = ctypes.sizeof (comp_device)

    comp_device_toc_entry = manifest_common.manifest_toc_entry (
        manifest_common.CFM_V2_COMPONENT_DEVICE_TYPE_ID, manifest_common.V2_BASE_TYPE_ID, 0, 0, 0,
        comp_device_len)

    comp_device_hash = manifest_common.generate_hash (comp_device, hash_engine)

    return comp_device, comp_device_toc_entry, comp_device_hash


#*************************************** Start of Script ***************************************

default_config = os.path.join (os.path.dirname (os.path.abspath (__file__)), CFM_CONFIG_FILENAME)
parser = argparse.ArgumentParser (description = 'Create a CFM')
parser.add_argument ('config', nargs = '?', default = default_config,
    help = 'Path to configuration file')
args = parser.parse_args ()

processed_xml, sign, key_size, key, key_type, hash_type, cfm_id, output, xml_version, empty, \
    max_num_rw_sections, selection_list = \
        manifest_common.load_xmls (args.config, None, manifest_types.CFM)

hash_engine = manifest_common.get_hash_engine (hash_type)
platform_id = selection_list["platform_id"]

components = {}
elements_list = []
toc_list = []
hash_list = []

for xml_key, xml_dict in processed_xml.items ():
    for component_key, component_dict in xml_dict.items ():
        if component_key in components:
            raise ValueError ("Component '{0}' defined in multiple XMLs".format (component_key))

        components.update ({component_key:component_dict})

platform_id, platform_id_toc_entry, platform_id_hash = \
    manifest_common.generate_platform_id_buf ({"platform_id": platform_id}, hash_engine)

cfm_len = ctypes.sizeof (platform_id)
elements_list.append (platform_id)
toc_list.append (platform_id_toc_entry)
hash_list.append (platform_id_hash)

if not empty:
    for component_type, component_dict in components.items ():
        num_pmr_digests = 0
        num_measurements = 0
        num_measurement_data = 0
        num_allowable_pfm = 0
        num_allowable_cfm = 0
        num_allowable_pcd = 0

        component_elements_list = []
        component_toc_list = []
        component_hash_list = []

        if "root_ca_digests" in component_dict:
            root_ca_digests, root_ca_digests_toc_entry, root_ca_digests_hash = \
                generate_root_ca_digests (component_dict["root_ca_digests"], hash_engine)

            cfm_len += ctypes.sizeof (root_ca_digests)
            component_elements_list.append (root_ca_digests)
            component_toc_list.append (root_ca_digests_toc_entry)
            component_hash_list.append (root_ca_digests_hash)

        if "pmr" in component_dict:
            pmr, pmr_toc_list, pmr_hash_list = generate_pmr (component_dict["pmr"], hash_engine)

            cfm_len += ctypes.sizeof (pmr)
            component_elements_list.append (pmr)
            component_toc_list.extend (pmr_toc_list)
            component_hash_list.extend (pmr_hash_list)

        if "pmr_digests" in component_dict:
            pmr_digests, num_pmr_digests, pmr_digests_toc_list, pmr_digests_hash_list = \
                generate_pmr_digests (component_dict["pmr_digests"], hash_engine)

            cfm_len += ctypes.sizeof (pmr_digests)
            component_elements_list.append (pmr_digests)
            component_toc_list.extend (pmr_digests_toc_list)
            component_hash_list.extend (pmr_digests_hash_list)

        if "measurements" in component_dict:
            measurements, num_measurements, measurements_toc_list, measurements_hash_list = \
                generate_measurements (component_dict["measurements"], hash_engine)

            cfm_len += ctypes.sizeof (measurements)
            component_elements_list.append (measurements)
            component_toc_list.extend (measurements_toc_list)
            component_hash_list.extend (measurements_hash_list)

        if "measurement_data" in component_dict:
            measurement_data, num_measurement_data, measurement_data_toc_list, \
                measurement_data_hash_list = generate_measurement_data (
                    component_dict["measurement_data"], hash_engine)

            cfm_len += ctypes.sizeof (measurement_data)
            component_elements_list.append (measurement_data)
            component_toc_list.extend (measurement_data_toc_list)
            component_hash_list.extend (measurement_data_hash_list)

        if "allowable_pfm" in component_dict:
            allowable_pfm, num_allowable_pfm, allowable_pfm_toc_list, allowable_pfm_hash_list = \
                generate_allowable_pfm (component_dict["allowable_pfm"], hash_engine)

            cfm_len += ctypes.sizeof (allowable_pfm)
            component_elements_list.append (allowable_pfm)
            component_toc_list.extend (allowable_pfm_toc_list)
            component_hash_list.extend (allowable_pfm_hash_list)

        if "allowable_cfm" in component_dict:
            allowable_cfm, num_allowable_cfm, allowable_cfm_toc_list, allowable_cfm_hash_list = \
                generate_allowable_cfm (component_dict["allowable_cfm"], hash_engine)

            cfm_len += ctypes.sizeof (allowable_cfm)
            component_elements_list.append (allowable_cfm)
            component_toc_list.extend (allowable_cfm_toc_list)
            component_hash_list.extend (allowable_cfm_hash_list)

        if "allowable_pcd" in component_dict:
            allowable_pcd, allowable_pcd_toc_entry, allowable_pcd_hash = generate_allowable_pcd (
                component_dict["allowable_pcd"], hash_engine)

            cfm_len += ctypes.sizeof (allowable_pcd)
            component_elements_list.append (allowable_pcd)
            component_toc_list.extend (allowable_pcd_toc_entry)
            component_hash_list.extend (allowable_pcd_hash)

            num_allowable_pcd = 1

        comp_device, comp_device_toc_entry, comp_device_hash = generate_comp_device (component_type,
            num_pmr_digests, num_measurements, num_measurement_data, num_allowable_pfm,
            num_allowable_cfm, num_allowable_pcd, component_dict["slot_num"],
            component_dict["attestation_protocol"], hash_engine)

        cfm_len += ctypes.sizeof (comp_device)
        elements_list.append (comp_device)
        toc_list.append (comp_device_toc_entry)
        hash_list.append (comp_device_hash)
        elements_list.extend (component_elements_list)
        toc_list.extend (component_toc_list)
        hash_list.extend (component_hash_list)

manifest_common.generate_manifest (hash_engine, hash_type, cfm_id, manifest_types.CFM, xml_version,
    sign, key, key_size, key_type, toc_list, hash_list, elements_list, cfm_len, output)

print ("Completed CFM generation: {0}".format (output))
