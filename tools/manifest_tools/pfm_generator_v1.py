"""
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the MIT license.
"""

from __future__ import print_function
from __future__ import unicode_literals
import os
import ctypes
import binascii
import argparse
import manifest_types
import manifest_common
from Crypto.PublicKey import RSA


PFM_CONFIG_FILENAME = "pfm_generator.config"
VALIDATE_ON_BOOT_FLAG = 1


# Table which indexes public keys used in this PFM file
pbkey_table = []

# List of all FW version strings
version_list = []

# These ctype structs resemble the format the PFM consumer utilizes
class pfm_fw_header (ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('length', ctypes.c_ushort),
                ('version_length', ctypes.c_ubyte),
                ('blank_byte', ctypes.c_ubyte),
                ('version_addr', ctypes.c_uint),
                ('img_count', ctypes.c_ubyte),
                ('rw_count', ctypes.c_ubyte),
                ('reserved', ctypes.c_ushort)]

class pfm_allowable_fw_header (ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('length', ctypes.c_ushort),
                ('fw_count', ctypes.c_ubyte),
                ('reserved', ctypes.c_ubyte)]

class pfm_public_key_header (ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('length', ctypes.c_ushort),
                ('key_length', ctypes.c_ushort),
                ('key_exponent', ctypes.c_uint),
                ('id', ctypes.c_ubyte),
                ('reserved', ctypes.c_ubyte * 3)]

class pfm_key_manifest_header (ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('length', ctypes.c_ushort),
                ('key_count', ctypes.c_ubyte),
                ('reserved', ctypes.c_ubyte)]

class pfm_flash_region (ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('start_addr', ctypes.c_uint),
                ('end_addr', ctypes.c_uint)]

class pfm_image_header (ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('length', ctypes.c_ushort),
                ('flags', ctypes.c_ushort),
                ('key_id', ctypes.c_ubyte),
                ('region_count', ctypes.c_ubyte),
                ('sig_length', ctypes.c_ushort)]

def process_pbkey (xml_list):
    """
    Iterate through all public keys used in this PFM and create a public key table.

    :param xml_list: List of parsed XMLs for different FW to be included in PFM
    """

    for _, xml in xml_list.items ():
        if "signed_imgs" in xml:
            for img in xml["signed_imgs"]:
                if "pbkey" in img:
                    pbkey = RSA.importKey(img["pbkey"])
                    img.pop("pbkey")
                    if pbkey not in pbkey_table:
                        pbkey_table.append (pbkey)
                        img["pbkey_index"] = len (pbkey_table) - 1
                    else:
                        img["pbkey_index"] =  pbkey_table.index(pbkey)

def generate_pfm (pfm_header_instance, allowable_fw_header_instance, allowable_fw_list,
        keys_header_instance, keys_list, platform_header_instance):
    """
    Create a PFM object from all the different PFM components

    :param pfm_header_instance: Instance of a PFM header
    :param allowable_fw_header_instance: Instance of a PFM allowable FW header
    :param allowable_fw_list: List of allowable FWs to be included in PFM
    :param keys_header_instance: Instance of a PFM key manifest header
    :param keys_list: List of public keys to be included in PFM
    :param platform_header_instance: Instance of a PFM platform header

    :return Instance of a PFM object
    """
    fw_size = allowable_fw_header_instance.length - ctypes.sizeof (allowable_fw_header_instance)
    keys_size = keys_header_instance.length - ctypes.sizeof (keys_header_instance)
    platform_size = ctypes.sizeof (platform_header_instance)

    class pfm (ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('manifest_header', manifest_common.manifest_header),
                    ('allowable_fw_header', pfm_allowable_fw_header),
                    ('allowable_fw', ctypes.c_ubyte * fw_size),
                    ('key_manifest_header', pfm_key_manifest_header),
                    ('pb_keys', ctypes.c_ubyte * keys_size),
                    ('platform', ctypes.c_ubyte * platform_size)]

    fw_buf = (ctypes.c_ubyte * fw_size)()
    fw_buf_len = manifest_common.move_list_to_buffer (fw_buf, 0, allowable_fw_list)

    keys_buf = (ctypes.c_ubyte * keys_size)()
    keys_buf_len = manifest_common.move_list_to_buffer (keys_buf, 0, keys_list)

    platform_buf = (ctypes.c_ubyte * platform_size)()
    ctypes.memmove (ctypes.addressof (platform_buf), ctypes.addressof (platform_header_instance),
        platform_size)

    return pfm (pfm_header_instance, allowable_fw_header_instance, fw_buf, keys_header_instance,
        keys_buf, platform_buf)

def generate_flash_region (filename, region_list):
    """
    Create a list of flash region struct instances from region list

    :param filename: XML filename
    :param region_list: List of flash regions

    :return List of flash region struct instances
    """

    flash_list = []

    for region in region_list:
        if "start" in region and "end" in region:
            start_addr = int (region["start"], 16)
            end_addr = int (region["end"], 16)

            if end_addr <= start_addr:
                raise ValueError ("Failed to generate PFM: Image has an invalid flash region - {0}"
                    .format (filename))

            flash_list.append (pfm_flash_region(start_addr, end_addr))

    return flash_list

def generate_img_instance (filename, img, regions, signature):
    """
    Create a list of signed image instances

    :param filename: Parsed XML file
    :param img: Signed or hashed image for which an image instance to generated
    :param regions: List of flash regions
    :param signature: Buffer containing either signature or hash of the image

    :return List of signed image instances
    """

    if "validate" not in img:
        raise KeyError ("Failed to generate PFM: Image has no validate flag - {0}".format (
            filename))
    if "pbkey_index" not in img:
        raise KeyError ("Failed to generate PFM: Image has no public key index - {0}".format (
            filename))

    flags = 1 if img["validate"] == "true" else 0
    header = pfm_image_header(0, flags, img["pbkey_index"], len (regions), len (signature))

    sig_arr = (ctypes.c_ubyte * len (signature)).from_buffer_copy (signature)
    region_arr = (pfm_flash_region * len (regions))(*regions)

    class pfm_signed_img (ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('header', pfm_image_header),
                    ('img_signature', ctypes.c_ubyte * len (signature)),
                    ('flash_regions', pfm_flash_region * len (regions))]

    return pfm_signed_img (header, sig_arr, region_arr)

def generate_signed_image (filename, img_list):
    """
    Create a list of signed image struct instances from image list

    :param filename: parsed XML file
    :param img_list: List of allowable firmware images

    :return List of signed image struct instances
    """

    signed_list = []

    for img in img_list:
        if "regions" not in img:
            raise KeyError ("Failed to generate PFM: Image has no regions list - {0}".format (
                filename))

        if "signature" not in img:
            raise KeyError ("Failed to generate PFM: Image has no signature - {0}".format (
                filename))

        regions = generate_flash_region(filename, img["regions"])
        img_instance = generate_img_instance(filename, img, regions, img["signature"])
        img_instance.header.length = ctypes.sizeof (img_instance)
        signed_list.append (img_instance)

    return signed_list

def generate_image_and_rw_region_list (filename, xml, version_addr, version_length):
    """
    Create a list of signed images and RW regions from parsed XML

    :param filename: parsed XML filename
    :param xml: Parsed XML
    :param version_addr: Address of the version string
    :param version_length: Length of the version string

    :return signed images list, rw regions list, rw regions array
    """

    signed_imgs_list = []
    rw_regions_list = []
    rw_regions_arr = None
    all_regions = []

    rw_regions_list = generate_flash_region (filename, xml["rw_regions"])
    rw_regions_arr = (pfm_flash_region * len (rw_regions_list)) (*rw_regions_list)
    signed_imgs_list = generate_signed_image (filename, xml["signed_imgs"])

    for region in rw_regions_list:
        manifest_common.check_region_address_validity (region.start_addr, region.end_addr)
        all_regions.append ([region.start_addr, region.end_addr])

    flags = 0
    for img in signed_imgs_list:
        flags |= (img.header.flags & VALIDATE_ON_BOOT_FLAG)
        for region in img.flash_regions:
            all_regions.append ([region.start_addr, region.end_addr])

            if (img.header.flags & VALIDATE_ON_BOOT_FLAG) == VALIDATE_ON_BOOT_FLAG:
                if ((version_addr + version_length - 1) <= region.end_addr and
                    version_addr >= region.start_addr):
                    version_addr_valid = True

    if not version_addr_valid:
        raise ValueError ("Failed to generate PFM: Version address not in a signed image with validate on boot flag set - {0}".format (
            filename))

    if flags == 0:
        raise ValueError ("Failed to generate PFM: XML has no signed images with validate on boot flag set - {0}".format (
            filename))

    all_regions.sort ()

    for i_region, region in enumerate (all_regions):
        for i_comp in range (i_region + 1, len (all_regions)):
            if region[1] >= all_regions[i_comp][0]:
                raise ValueError ("Failed to generate PFM: XML has overlapping regions - {0}".format (
                    filename))

    return rw_regions_arr, len (rw_regions_list), signed_imgs_list

def generate_allowable_fw_list (xml_list):
    """
    Create a list of allowable firmware from parsed XML list

    :param xml_list: List of parsed XML of firmware to be included in PFM

    :return list of allowable firmware struct instances
    """

    fw_list = []

    for filename, xml in xml_list.items ():
        version_addr = int (xml["version_addr"], 16)
        unused_byte = int (xml["unused_byte"], 16)
        version_addr_valid = False

        for version in version_list:
            if version == xml["version_id"]:
                raise KeyError ("Failed to generate PFM: Duplicate version ID - {0}".format (
                    xml["version_id"]))
            elif version.startswith (xml["version_id"]) or xml["version_id"].startswith (version):
                raise ValueError ("Failed to generate PFM: Ambiguous version ID - {0}, {1}".format (
                    xml["version_id"], version))

        version_list.append (xml["version_id"])

        manifest_common.check_maximum (unused_byte, 255, "Unused byte")
        manifest_common.check_maximum (len (xml["version_id"]), 255, 
            "Version ID {0} string length".format (xml["version_id"]))

        header = pfm_fw_header (0, len (xml["version_id"]), unused_byte, version_addr,
            len (xml["signed_imgs"]), len (xml["rw_regions"]), 0)

        rw_regions_buf, rw_regions_size, signed_imgs_list = generate_image_and_rw_region_list (
            filename, xml, version_addr, header.version_length)

        signed_imgs_size = 0
        for img in signed_imgs_list:
            signed_imgs_size = signed_imgs_size + ctypes.sizeof (img)

        signed_imgs_buf = (ctypes.c_ubyte * signed_imgs_size)()
        signed_imgs_buf_len = manifest_common.move_list_to_buffer (signed_imgs_buf, 0, 
            signed_imgs_list)

        manifest_common.check_maximum (len (xml["version_id"]), 255, 
            "Version ID {0} length".format (xml["version_id"]))
        padding, padding_len = manifest_common.generate_4byte_padding_buf (len (xml["version_id"]))

        class pfm_allowable_fw(ctypes.LittleEndianStructure):
            _pack_ = 1
            _fields_ = [('header', pfm_fw_header),
                        ('version_id', ctypes.c_char * len (xml["version_id"])),
                        ('padding', ctypes.c_ubyte * padding_len),
                        ('rw_regions', pfm_flash_region * rw_regions_size),
                        ('signed_imgs', ctypes.c_ubyte * signed_imgs_size)]

        fw = pfm_allowable_fw(header, xml["version_id"].encode ('utf-8'), padding, rw_regions_buf, 
            signed_imgs_buf)
        fw.header.length = ctypes.sizeof (pfm_allowable_fw)
        fw_list.append (fw)

    return fw_list

def generate_allowable_fw_header (fw_list):
    """
    Create an allowable FW header from an allowable FW list

    :param fw_list: List of allowable FW to be included in PFM

    :return Allowable FW header instance
    """

    size = ctypes.sizeof (pfm_allowable_fw_header)
    for fw in fw_list:
        size = size + ctypes.sizeof (fw)

    return pfm_allowable_fw_header (size, len (fw_list), 0)

def generate_key_instance (header, modulus):
    """
    Create a key instance from header and modulus

    :param header: PFM public key header
    :param modulus: List of public key modulus digits

    :return Public key instance
    """

    arr = (ctypes.c_ubyte * len (modulus)).from_buffer_copy (modulus)

    class pfm_public_key (ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('header', pfm_public_key_header),
                    ('public_key_modulus', ctypes.c_ubyte * len (modulus))]

    return pfm_public_key (header, arr)

def generate_pbkey_list ():
    """
    Create a public key list from the public key table

    :return List of public key instances
    """

    keys_list = []

    for pub_key in pbkey_table:
        reserved_buf = (ctypes.c_ubyte * 3)()
        ctypes.memset (reserved_buf, 0, 3)
        mod_fmt = "%%0%dx" % (pub_key.n.bit_length() // 4)
        modulus = binascii.a2b_hex (mod_fmt % pub_key.n)

        header = pfm_public_key_header(0, len (modulus), pub_key.e, pbkey_table.index (pub_key),
            reserved_buf)

        key = generate_key_instance (header, modulus)
        key.header.length = ctypes.sizeof (key)
        keys_list.append (key)

    return keys_list

def generate_pbkey_header (keys_list):
    """
    Create a public key manifest header from list of public key objects

    :param keys_list: List of public key objects

    :return Public key manifest header
    """

    size = ctypes.sizeof (pfm_key_manifest_header)

    for key in keys_list:
        size = size + ctypes.sizeof (key)

    return pfm_key_manifest_header (size, len (keys_list), 0)

def generate_platform_info (platform_id):
    """
    Create the platform information section of the manifest.

    :param platform_id: Platform ID string

    :return Platform manifest section
    """
    
    manifest_common.check_maximum (len (platform_id), 255, "Platform ID {0} length".format (
        platform_id))
    padding, padding_len = manifest_common.generate_4byte_padding_buf (len (platform_id))

    class manifest_platform_id (ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('length', ctypes.c_ushort),
                    ('id_length', ctypes.c_ubyte),
                    ('reserved', ctypes.c_ubyte),
                    ('platform_id', ctypes.c_char * len (platform_id)),
                    ('padding', ctypes.c_ubyte * padding_len)]

    return manifest_platform_id (ctypes.sizeof (manifest_platform_id), len (platform_id), 0, 
        platform_id.encode ('utf-8'), padding)

def generate_v1_pfm (pfm_id, key_size, hash_type, key_type, processed_xml, bypass, 
    sign, key, output):
    """
    Generate v1 PFM manifest from processed XML

    :param pfm_id: PFM id
    :param key_size: Size of signing key, optional
    :param hash_type: Hashing algorithm
    :param key_type: Signing key algorithm, optional 
    :param processed_xml: List of parsed XML files to process for PFM
    :param bypass: Boolean indicating whether to generate bypass PFM or not
    :param sign: Boolean indicating whether to sign manifest or not
    :param key: Key to use for signing
    :param output: Output filename
    """

    manifest_header = manifest_common.generate_manifest_header (pfm_id, key_size, 
        manifest_types.PFM, hash_type, key_type, manifest_types.VERSION_1)
    manifest_header_len = ctypes.sizeof (manifest_header)

    process_pbkey (processed_xml)

    if (bypass):
        allowable_fw_list = []
        keys_list = []
    else:
        allowable_fw_list = generate_allowable_fw_list (processed_xml)
        keys_list = generate_pbkey_list ()

    allowable_fw_header = generate_allowable_fw_header (allowable_fw_list)

    keys_header = generate_pbkey_header (keys_list)

    platform_id = manifest_common.get_platform_id_from_xml_list (processed_xml)
    platform_header = generate_platform_info (platform_id)

    manifest_header.length = ctypes.sizeof (manifest_header) + keys_header.length + \
        allowable_fw_header.length + manifest_header.sig_length + ctypes.sizeof (platform_header)

    pfm = generate_pfm (manifest_header, allowable_fw_header, allowable_fw_list, keys_header,
        keys_list, platform_header)

    manifest_common.write_manifest (manifest_types.VERSION_1, sign, pfm, key, key_size, key_type, 
        output, manifest_header.length - manifest_header.sig_length, manifest_header.sig_length)

