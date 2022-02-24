"""
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the MIT license.
"""

from __future__ import print_function
from __future__ import unicode_literals
import os
import copy
import ctypes
import argparse
import manifest_types
import manifest_common
import pfm_generator_v1


PFM_CONFIG_FILENAME = "pfm_generator.config"


def generate_rw_regions_buf (xml_rw):
    """
    Create a buffer of pfm_rw_region struct instances from parsed XML list

    :param xml_rw: List of parsed XML of RW regions to be included in PFM

    :return RW regions buffer, length of RW regions buffer, number of RW regions, list of all
        regions
    """

    if xml_rw is None or len (xml_rw) < 1:
        return (ctypes.c_ubyte * 0), 0, 0, []

    class pfm_rw_region (ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('rw_flags', ctypes.c_ubyte),
                    ('reserved', ctypes.c_ubyte * 3),
                    ('rw_start_addr', ctypes.c_uint),
                    ('rw_end_addr', ctypes.c_uint)]

    num_rw_regions = len (xml_rw)
    rw_regions_buf = (ctypes.c_ubyte * (ctypes.sizeof (pfm_rw_region) * num_rw_regions)) ()
    rw_regions_len = 0
    all_regions = []

    reserved_buf = (ctypes.c_ubyte * 3) ()
    ctypes.memset (reserved_buf, 0, 3)
    for rw_region in xml_rw:
        rw_start_addr = int (manifest_common.get_key_from_dict (rw_region, "start",
            "RW region start address"), 16)
        rw_end_addr = int (manifest_common.get_key_from_dict (rw_region, "end",
            "RW region end address"), 16)
        manifest_common.check_region_address_validity (rw_start_addr, rw_end_addr)

        all_regions.append ([rw_start_addr, rw_end_addr])

        rw_flags = int (manifest_common.get_key_from_dict (rw_region, "operation_fail",
            "Operation on Fail"), 16)

        rw_region_body = pfm_rw_region (rw_flags, reserved_buf, rw_start_addr, rw_end_addr)
        rw_regions_len = manifest_common.move_list_to_buffer (rw_regions_buf, rw_regions_len,
            [rw_region_body])

    return rw_regions_buf, rw_regions_len, num_rw_regions, all_regions

def generate_signed_imgs_buf (xml_signed_imgs):
    """
    Create a buffer of pfm_signed_image struct instances from parsed XML list

    :param xml_signed_imgs: List of parsed XML of signed images to be included in PFM

    :return Signed images buffer, length of signed images buffer, number of signed images, list of
        all regions
    """

    if xml_signed_imgs is None or len (xml_signed_imgs) < 1:
        return None, 0, 0

    class pfm_signed_image_header (ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('hash_type', ctypes.c_ubyte),
                    ('region_count', ctypes.c_ubyte),
                    ('image_flags', ctypes.c_ubyte),
                    ('reserved', ctypes.c_ubyte)]

    class pfm_signed_image_region (ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('img_start_addr', ctypes.c_uint),
                    ('img_end_addr', ctypes.c_uint)]

    signed_imgs = []
    signed_imgs_len = 0
    num_signed_imgs = len (xml_signed_imgs)
    all_regions = []

    for signed_img in xml_signed_imgs:
        hash_type = int (manifest_common.get_key_from_dict (signed_img, "hash_type", "Hash type"),
            16)
        validate = manifest_common.get_key_from_dict (signed_img, "validate", "Validate region")
        signed_img_hash = manifest_common.get_key_from_dict (signed_img, "hash",
            "Signed image hash")
        signed_img_hash_arr = (ctypes.c_ubyte * len (signed_img_hash)).from_buffer_copy (
            signed_img_hash)
        signed_img_hash_arr_len = ctypes.sizeof (signed_img_hash_arr)

        img_flags = 1 if validate == "true" else 0

        num_signed_regions = 0
        signed_regions_len = 0

        if "regions" in signed_img:
            signed_regions_buf = (ctypes.c_ubyte * (ctypes.sizeof (pfm_signed_image_region) * \
                len (signed_img["regions"]))) ()

            for region in signed_img["regions"]:
                img_start_addr = int (manifest_common.get_key_from_dict (region, "start",
                    "Signed image start address"), 16)
                img_end_addr = int (manifest_common.get_key_from_dict (region, "end",
                    "Signed image end address"), 16)
                manifest_common.check_region_address_validity (img_start_addr, img_end_addr, False)

                all_regions.append ([img_start_addr, img_end_addr])

                signed_image_region = pfm_signed_image_region (img_start_addr, img_end_addr)
                signed_regions_len = manifest_common.move_list_to_buffer (signed_regions_buf,
                    signed_regions_len, [signed_image_region])
                num_signed_regions += 1

        signed_img_buf = (ctypes.c_ubyte * (ctypes.sizeof (pfm_signed_image_header) + \
            signed_regions_len + signed_img_hash_arr_len)) ()
        signed_img_header = pfm_signed_image_header (hash_type, num_signed_regions, img_flags, 0)

        signed_img_len = manifest_common.move_list_to_buffer (signed_img_buf, 0, [signed_img_header,
            signed_img_hash_arr, signed_regions_buf])

        signed_imgs_len += signed_img_len
        signed_imgs.append (signed_img_buf)

    signed_imgs_buf = (ctypes.c_ubyte * signed_imgs_len) ()
    signed_img_len = manifest_common.move_list_to_buffer (signed_imgs_buf, 0, signed_imgs)

    return signed_imgs_buf, signed_imgs_len, len (signed_imgs), all_regions

def generate_permutations (src_list):
    """
    Generate all possible permutations of 1 version from each FW type in incoming src_list

    :param src_list: List of FW types, with a list of FW versions per FW type, and a list of regions
        per FW version

    :return A list of all possible permutations
    """

    new_list = list (src_list)
    fw_type = new_list.pop (0)
    total_permutations = []

    for version in fw_type:
        if not new_list:
            total_permutations.append (list (version))
        else:
            permutations = generate_permutations (new_list)

            for permutation in permutations:
                permutation.extend (version)

            total_permutations.extend (permutations)

    return total_permutations

def check_max_rw_sections (all_rw_regions, max_rw_sections):
    """
    Ensure RW regions fit into maximum number of RW sections

    :param all_rw_regions: All RW regions for each FW type
    :param max_rw_sections: Number of non-contiguous RW sections supported
    """

    all_rw_permutations = generate_permutations (all_rw_regions)

    for permutation in all_rw_permutations:
        permutation_copy = copy.deepcopy (permutation)
        permutation_copy = sorted (permutation_copy)

        for i_region in range (len (permutation_copy) - 1, 0, -1):
            region1 = permutation_copy[i_region - 1]
            region2 = permutation_copy[i_region]

            if manifest_common.check_if_regions_contiguous (region1, region2):
                permutation_copy[i_region - 1][1] = permutation_copy[i_region][1]
                permutation_copy.remove (permutation_copy[i_region])

        if len (permutation_copy) > max_rw_sections:
            raise ValueError (
                "Number of non-contiguous RW regions greater than maximum defined: {0} vs {1}".format (
                    len (permutation_copy), max_rw_sections))

def check_overlapping_regions (all_regions):
    """
    Ensure no regions overlap with regions from other FW types

    :param all_regions: All RW and signed image regions for each FW type
    """

    for i_fw_type1 in range (len (all_regions)):
        for version1 in all_regions[i_fw_type1]:
            for i_region1 in range (len (version1)):
                region1 = version1[i_region1]

                for i_region2 in range (i_region1 + 1, len (version1)):
                    region2 = version1[i_region2]

                    if manifest_common.check_if_regions_overlap (region1, region2):
                        raise ValueError (
                            "Region at [0x{0}:0x{1}] overlapping with region at [0x{2}:0x{3}]".format (
                                format (region1[0], 'x'), format (region1[1], 'x'),
                                format (region2[0], 'x'), format (region2[1], 'x')))

                for i_fw_type2 in range (i_fw_type1 + 1, len (all_regions)):
                    for version2 in all_regions[i_fw_type2]:
                        for region2 in version2:
                            if manifest_common.check_if_regions_overlap (region1, region2):
                                raise ValueError (
                                    "Region at [0x{0}:0x{1}] overlapping with region at [0x{2}:0x{3}]".format (
                                        format (region1[0], 'x'), format (region1[1], 'x'),
                                        format (region2[0], 'x'), format (region2[1], 'x')))

def generate_fw_versions_list (xml_list, hash_engine, max_rw_sections):
    """
    Create a list of FW version struct instances for each FW type from parsed XML list

    :param xml_list: List of parsed XML of FW versions to be included in PFM
    :param hash_engine: Hashing engine
    :param max_rw_sections: Maximum number of non-contiguous RW sections supported

    :return FW buffer, number of FW, list of FW TOC entries, list of FW hashes, Unused byte
    """

    if xml_list is None or len (xml_list) < 1:
        return None, 0, None, None, 0

    fw_version_list = {}
    runtime_update_list = {}
    unused_byte = None
    all_regions = {}
    all_rw_regions = {}

    for filename, xml in xml_list.items():
        fw_type = manifest_common.get_key_from_dict (xml, "fw_type", "FW Type")
        manifest_common.check_maximum (len (fw_type), 255, "FW type {0} string length".format (
            fw_type))

        if fw_type not in fw_version_list:
            fw_version_list[fw_type] = dict ()
            all_regions[fw_type] = []
            all_rw_regions[fw_type] = []

        unused_byte_val = int (manifest_common.get_key_from_dict (xml, "unused_byte",
            "Unused Byte"), 16)
        manifest_common.check_maximum (unused_byte_val, 255, "Unused byte")

        if unused_byte is None:
            unused_byte = unused_byte_val
        else:
            if unused_byte_val != unused_byte:
                raise ValueError ("Different unused byte values found: ({0}) vs ({1}) - {2}".format (
                    unused_byte_val, unused_byte, filename))

        runtime_update_val = manifest_common.get_key_from_dict (xml, "runtime_update",
            "Runtime Update")
        if fw_type not in runtime_update_list:
            runtime_update_list[fw_type] = runtime_update_val
        else:
            if runtime_update_list[fw_type] != runtime_update_val:
                raise ValueError (
                    "Different runtime update values found for FW type ({0}): ({1}) vs ({2}) - {3}".format (
                        fw_type, runtime_update_val, runtime_update_list[fw_type], filename))

        version_addr = int (manifest_common.get_key_from_dict (xml, "version_addr",
            "Version Address"), 16)

        version_id = manifest_common.get_key_from_dict (xml, "version_id", "Version ID")
        version_id_len = len (version_id)
        manifest_common.check_maximum (version_id_len, 255, "Version ID {0} length".format (
            version_id))
        padding, padding_len = manifest_common.generate_4byte_padding_buf (version_id_len)

        all_regions_list = []

        if "rw_regions" in xml:
            rw_regions_buf, rw_regions_len, num_rw_regions, rw_regions = generate_rw_regions_buf (
                xml["rw_regions"])
            all_regions_list.extend (rw_regions)
            all_rw_regions[fw_type].append (rw_regions)

        if "signed_imgs" in xml:
            signed_imgs_buf, signed_imgs_len, num_signed_imgs, signed_regions = \
                generate_signed_imgs_buf (xml["signed_imgs"])
            all_regions_list.extend (signed_regions)

        all_regions[fw_type].append (all_regions_list)

        class pfm_fw_version (ctypes.LittleEndianStructure):
            _pack_ = 1
            _fields_ = [('image_count', ctypes.c_ubyte),
                        ('rw_count', ctypes.c_ubyte),
                        ('version_length', ctypes.c_ubyte),
                        ('reserved', ctypes.c_ubyte),
                        ('version_addr', ctypes.c_uint),
                        ('version_id', ctypes.c_char * version_id_len),
                        ('version_id_padding', ctypes.c_ubyte * padding_len),
                        ('rw_regions', ctypes.c_ubyte * rw_regions_len),
                        ('signed_imgs', ctypes.c_ubyte * signed_imgs_len)]

        fw_version = pfm_fw_version (num_signed_imgs, num_rw_regions, version_id_len, 0,
            version_addr, version_id.encode ('utf-8'), padding, rw_regions_buf, signed_imgs_buf)

        for prev_version_id, prev_fw_version in fw_version_list[fw_type].items ():
            if prev_version_id == version_id:
                raise KeyError (
                    "Failed to generate PFM: Duplicate version ID - {0} in FW type {1}".format (
                        version_id, fw_type))
            elif prev_version_id.startswith(version_id) or version_id.startswith(prev_version_id):
                raise ValueError (
                    "Failed to generate PFM: Ambiguous version ID - {0}, {1} in FW type {2}".format (
                        prev_version_id, version_id, fw_type))

        fw_version_list[fw_type].update ({version_id: fw_version})

    all_regions_list = []
    all_rw_regions_list = []

    for fw_id, fw_id_list in all_regions.items():
        all_regions_list.append (fw_id_list)
    for fw_id, fw_id_list in all_rw_regions.items():
        all_rw_regions_list.append (fw_id_list)

    check_overlapping_regions (all_regions_list)
    check_overlapping_regions (all_rw_regions_list)
    check_max_rw_sections (all_rw_regions_list, max_rw_sections)

    return fw_version_list, runtime_update_list, unused_byte

def generate_fw_buf (xml_list, hash_engine, max_rw_sections):
    """
    Create a buffer of FW struct instances from parsed XML list

    :param xml_list: List of parsed XML of FW to be included in PFM
    :param hash_engine: Hashing engine
    :param max_rw_sections: Maximum number of non-contiguous RW sections supported

    :return FW buffer, number of FW, list of FW TOC entries, list of FW hashes, Unused byte
    """

    if xml_list is None or len (xml_list) < 1:
        return None, 0, None, None, 0

    fw_list = []
    fw_toc_list = []
    fw_hash_list = []
    num_fw = 0
    fw_len = 0

    fw_version_list, runtime_update_list, unused_byte = generate_fw_versions_list (xml_list,
        hash_engine, max_rw_sections)

    for fw_id, fw_versions in fw_version_list.items ():
        fw_id_len = len (fw_id)
        manifest_common.check_maximum (fw_id_len, 255, "FW ID {0} length".format (fw_id))
        padding, padding_len = manifest_common.generate_4byte_padding_buf (fw_id_len)

        class pfm_fw (ctypes.LittleEndianStructure):
            _pack_ = 1
            _fields_ = [('version_count', ctypes.c_ubyte),
                        ('fw_id_length', ctypes.c_ubyte),
                        ('fw_flags', ctypes.c_ubyte),
                        ('reserved', ctypes.c_ubyte),
                        ('fw_id', ctypes.c_char * fw_id_len),
                        ('fw_id_padding', ctypes.c_ubyte * padding_len)]

        fw_flags = 0 if runtime_update_list[fw_id] == "false" else 1
        fw = pfm_fw (len (fw_versions), fw_id_len, fw_flags, 0, fw_id.encode ('utf-8'), padding)
        fw_toc_entry = manifest_common.manifest_toc_entry (manifest_common.PFM_V2_FW_TYPE_ID,
            manifest_common.V2_BASE_TYPE_ID, 1, 0, 0, ctypes.sizeof (fw))
        fw_hash = manifest_common.generate_hash (fw, hash_engine)

        fw_list.append (fw)
        fw_toc_list.append (fw_toc_entry)
        fw_hash_list.append (fw_hash)
        fw_len += ctypes.sizeof (fw)

        for version_id, fw_version in fw_versions.items ():
            fw_list.append (fw_version)
            fw_len += ctypes.sizeof (fw_version)

            fw_version_toc_entry = manifest_common.manifest_toc_entry (
                manifest_common.PFM_V2_FW_VERSION_TYPE_ID, manifest_common.PFM_V2_FW_TYPE_ID, 1,
                0, 0, ctypes.sizeof (fw_version))
            fw_toc_list.append (fw_version_toc_entry)

            fw_version_hash = manifest_common.generate_hash (fw_version, hash_engine)
            fw_hash_list.append (fw_version_hash)

        num_fw += 1

    fw_buffer = (ctypes.c_ubyte * fw_len) ()
    fw_buffer_len = manifest_common.move_list_to_buffer (fw_buffer, 0, fw_list)

    return fw_buffer, num_fw, fw_toc_list, fw_hash_list, unused_byte

def generate_flash_device_buf (hash_engine, unused_byte, fw_count):
    """
    Create a buffer of FW struct instances from parsed XML list

    :param hash_engine: Hashing engine
    :param unused_byte: Unused byte
    :param fw_count: Number of FW types in flash device

    :return Flash device buffer, Flash device TOC entry, Flash device hash
    """

    class pfm_flash_device (ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('blank_byte', ctypes.c_ubyte),
                    ('fw_count', ctypes.c_ubyte),
                    ('reserved', ctypes.c_ushort)]

    flash_device = pfm_flash_device (unused_byte, fw_count, 0)
    flash_device_toc_entry = manifest_common.manifest_toc_entry (
        manifest_common.PFM_V2_FLASH_DEVICE_TYPE_ID, manifest_common.V2_BASE_TYPE_ID, 0, 0, 0,
        ctypes.sizeof (flash_device))
    flash_device_hash = manifest_common.generate_hash (flash_device, hash_engine)

    return flash_device, flash_device_toc_entry, flash_device_hash

#*************************************** Start of Script ***************************************

default_config = os.path.join (os.path.dirname (os.path.abspath (__file__)), PFM_CONFIG_FILENAME)
parser = argparse.ArgumentParser (description = 'Create a PFM')
parser.add_argument ('config', nargs = '?', default = default_config,
    help = 'Path to configuration file')
parser.add_argument ('--bypass', action = 'store_true', help = 'Create a bypass mode PFM')
args = parser.parse_args ()

processed_xml, sign, key_size, key, key_type, hash_type, pfm_id, output, xml_version, empty, \
    max_rw_sections, selection_list = \
        manifest_common.load_xmls (args.config, None, manifest_types.PFM)

if xml_version == manifest_types.VERSION_2:
    elements_list = []
    toc_list = []
    hash_list = []

    hash_engine = manifest_common.get_hash_engine (hash_type)

    platform_id = manifest_common.get_platform_id_from_xml_list (processed_xml)
    platform_id, platform_id_toc_entry, platform_id_hash = \
        manifest_common.generate_platform_id_buf ({"platform_id": platform_id}, hash_engine)

    pfm_len = ctypes.sizeof (platform_id)
    elements_list.append (platform_id)
    toc_list.append (platform_id_toc_entry)
    hash_list.append (platform_id_hash)

    if not args.bypass:
        fw, num_fw, fw_toc_entries, fw_hashes, unused_byte = generate_fw_buf (processed_xml,
            hash_engine, max_rw_sections)

        flash_device, flash_device_toc_entry, flash_device_hash = generate_flash_device_buf (
            hash_engine, unused_byte, num_fw)

        pfm_len += ctypes.sizeof (flash_device)
        elements_list.append (flash_device)
        toc_list.append (flash_device_toc_entry)
        hash_list.append (flash_device_hash)

        pfm_len += ctypes.sizeof (fw)
        elements_list.append (fw)
        toc_list.extend (fw_toc_entries)
        hash_list.extend (fw_hashes)

    manifest_common.generate_manifest (hash_engine, hash_type, pfm_id, manifest_types.PFM,
        xml_version, sign, key, key_size, key_type, toc_list, hash_list, elements_list, pfm_len,
        output)

else:
    pfm_generator_v1.generate_v1_pfm (pfm_id, key_size, hash_type, key_type, processed_xml,
        args.bypass, sign, key, output)

print ("Completed PFM generation: {0}".format (output))
