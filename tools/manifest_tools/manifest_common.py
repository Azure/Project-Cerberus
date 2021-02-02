"""
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the MIT license.
"""

from __future__ import print_function
from __future__ import unicode_literals
import ctypes
import sys
import os
import traceback
from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC
from Crypto.Signature import PKCS1_v1_5
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Hash import SHA384
from Crypto.Hash import SHA512
import manifest_types
import manifest_parser


PFM_MAGIC_NUM = int("0x504D", 16)
CFM_MAGIC_NUM = int("0xA592", 16)
PCD_MAGIC_NUM = int("0x8EBC", 16)

PFM_V2_MAGIC_NUM = int("0x706D", 16)

PFM_V2_PLATFORM_TYPE_ID = int("0x00", 16)
PFM_V2_FLASH_DEVICE_TYPE_ID = int("0x10", 16)
PFM_V2_FW_TYPE_ID = int("0x11", 16)
PFM_V2_FW_VERSION_TYPE_ID = int("0x12", 16)
PFM_V2_TOP_ELEMENT = int ("0xff", 16)

class manifest_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('length', ctypes.c_ushort),
                ('magic', ctypes.c_ushort),
                ('id', ctypes.c_uint),
                ('sig_length', ctypes.c_ushort),
                ('sig_type', ctypes.c_ubyte),
                ('reserved', ctypes.c_ubyte)]

class manifest_toc_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('entry_count', ctypes.c_ubyte),
                ('hash_count', ctypes.c_ubyte),
                ('hash_type', ctypes.c_ubyte),
                ('reserved', ctypes.c_ubyte)]

class manifest_toc_element(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('type_id', ctypes.c_ubyte),
                ('parent', ctypes.c_ubyte),
                ('format', ctypes.c_ubyte),
                ('hash_id', ctypes.c_ubyte),
                ('offset', ctypes.c_ushort),
                ('length', ctypes.c_ushort)]

def load_config (config_file):
    """
    Load configuration options from file

    :param config_file: Path for a text file containing config options

    :return Parsed configuration
    """

    config = {}
    config["id"] = 0
    config["xml_list"] = []
    config["prv_key_path"] = ""
    config["output"] = ""
    config["key_size"] = ""
    config["hash_type"] = ""
    config["key_type"] = ""

    with open (config_file, 'r') as fh:
        data = fh.readlines ()

    if not data:
        print("Failed to load configuration")
        sys.exit(1)

    for string in data:
        string = string.replace("\n", "")
        string = string.replace("\r", "")

        if string.startswith("ID"):
            config["id"] = string.split("=")[-1].strip()
        elif string.startswith("Output"):
            config["output"] = string.split("=")[-1].strip()
        elif string.startswith("KeySize"):
            config["key_size"] = string.split("=")[-1].strip()
        elif string.startswith("KeyType"):
            config["key_type"] = string.split("=")[-1].strip()
        elif string.startswith("HashType"):
            config["hash_type"] = string.split("=")[-1].strip()
        elif string.startswith("Key"):
            config["prv_key_path"] = string.split("=")[-1].strip()
        else:
            config["xml_list"].append(string)

    return config

def load_key(key_type, key_size, prv_key_path):
    """
    Load private RSA/ECC key to sign manifest from provided path. If no valid key can be imported,
    key size will be what is provided. Otherwise, key size will be size of key imported

    :param key_type: Provided key type
    :param key_size: Provided key_size
    :param prv_key_path: Provided private key path

    :return <Sign manifest or not> <key_size> <Key to use for signing>
    """

    if prv_key_path:
        try:
            key = None
            if key_type == 1:
                key = ECC.import_key(open(prv_key_path).read())
                keysize = int(key.pointQ.size_in_bytes())
            else:
                key = RSA.importKey(open(prv_key_path).read())
                keysize = int(key.n.bit_length()/8)

        except Exception:
            print("Unsigned PFM will be generated, provided {1} key could not be imported: {0}".format(prv_key_path, "ECC" if key_type == 1 else "RSA"))
            traceback.print_exc ()
            return False, key_size, None

        return True, keysize, key
    else:
        print("No RSA private key provided in config, unsigned PFM will be generated.")
        return False, key_size, None

def generate_manifest_header(manifest_id, key_size, manifest_type, hash_type, key_type, manifest_version):
    """
    Create a manifest header

    :param manifest_id: Manifest id
    :param key_size: Size of RSA key
    :param manifest_type: Manifest type
    :param manifest_version: Manifest version

    :return Instance of a manifest header
    """

    if manifest_type == manifest_types.PFM:
        if manifest_version == manifest_types.VERSION_1:
            magic_num = PFM_MAGIC_NUM
        else:
            magic_num = PFM_V2_MAGIC_NUM
    elif manifest_type == manifest_types.CFM:
        magic_num = CFM_MAGIC_NUM
    elif manifest_type == manifest_types.PCD:
        magic_num = PCD_MAGIC_NUM
    else:
        raise ValueError ("Unknown manifest type: {0}".format (manifest_type))

    sig_len = 0
    sig_type = 0
    key_strength = 0
    if key_size is not None:
        sig_len = key_size
        if key_type is not None:
            if key_type == 1:
                sig_len = ((key_size + 1) * 2) + 6
                key_strength = 2 if key_size == 66 else 1 if key_size == 48 else 0
            else:
                key_strength = 2 if key_size == 512 else 1 if key_size == 384 else 0

            sig_type |= key_type << 6 | key_strength << 3

        if hash_type is not None:
            sig_type |= hash_type << 0

    return manifest_header(0, magic_num, int(manifest_id), sig_len, sig_type, 0)

def load_xmls (config_filename, max_num_xmls, xml_type):
    """
    Load XMLs listed in config file

    :param config_filename: Path to config file
    :param max_num_xmls: Maximum number of XMLs that can be loaded, set to NULL if no limit
    :param xml_type: Type of XML

    :return list of XML elements, boolean indicating whether to sign output or not, key size,
        key to use for signing, output ID, output filename and manifest xml version
    """

    config = load_config (config_filename)
    key_size = None
    prv_key_path = None
    key_type = 0
    hash_type = None
    sign = False

    if "key_type" in config and config["key_type"]:
        if config["key_type"] == "ECC":
            key_type = 1
    if "hash_type" in config and config["hash_type"]:
        hash_type = 2 if config["hash_type"] == "SHA512" else 1 if config["hash_type"] == "SHA384" else 0
    if "key_size" in config and config["key_size"]:
        key_size = int (config["key_size"])

    if "prv_key_path" in config and config["prv_key_path"]:
        prv_key_path = config["prv_key_path"]

    if max_num_xmls and (len (config["xml_list"]) > max_num_xmls):
        raise RuntimeError ("Too many XML files provided: {0}".format (len (config["xml_list"])))

    sign, key_size, key = load_key (key_type, key_size, prv_key_path)

    processed_xml = {}
    xml_version = None

    for xml in config["xml_list"]:
        parsed_xml = manifest_parser.load_and_process_xml (xml, xml_type)

        if parsed_xml is None:
            raise RuntimeError ("Failed to parse XML: {0}".format(xml))
        else:
            curr_xml_version = manifest_types.VERSION_1

            if "fw_type" in parsed_xml:
                curr_xml_version = manifest_types.VERSION_2

            if xml_version is None:
                xml_version = curr_xml_version

            if xml_version != curr_xml_version:
                raise RuntimeError("Failed to generate PFM: XML version is different - {0}".format(xml))

        processed_xml.update({xml:parsed_xml})

    return processed_xml, sign, key_size, key, key_type, hash_type, config["id"], config["output"], xml_version

def write_manifest(xml_version, sign, manifest, key, key_size, key_type, output_filename,
    manifest_length, sig_length):
    """
    Write manifest generated to provided path.

    :param xml_version: manifest xml version
    :param sign: Boolean indicating whether to sign manifest or not
    :param manifest: Generated manifest to write
    :param key: Key to use for signing
    :param key_size: Size of key used for signing
    :param key_type: Type of Key used for signing
    :param output_filename: Name to use for output file
    :param manifest_length: The manifest length
    :param sig_length: Signature length

    """

    if ctypes.sizeof(manifest) > (65535 - sig_length):
        raise ValueError("Manifest is too large - {0}".format(ctypes.sizeof(manifest)))

    if ctypes.sizeof(manifest) != manifest_length:
        raise ValueError("Manifest doesn't match output size")

    if manifest.manifest_header.length != manifest_length + sig_length:
        raise ValueError("Manifest length is not set correctly")

    if key_type > 1:
        raise ValueError("Manifest Signing key type is not set correctly")

    sha_algo = SHA512 if key_size == 512 else SHA384 if key_size == 384 else SHA256

    if xml_version == manifest_types.VERSION_1 and key_type == 1:
        raise ValueError("Manifest Signing key type not supported for version 1 xml")

    if sign:
        manifest_hash_buf = (ctypes.c_ubyte * manifest_length)()
        ctypes.memmove(ctypes.addressof(manifest_hash_buf), ctypes.addressof(manifest), manifest_length)
        h = sha_algo.new(manifest_hash_buf)

        if key_type == 1:
            signer = DSS.new(key, 'fips-186-3', 'der')
        else:
            signer = PKCS1_v1_5.new(key)

        signature = signer.sign(h)
        signature_buf_len = len(signature) if len(signature) < sig_length else sig_length
        signature_buf = (ctypes.c_ubyte * signature_buf_len).from_buffer_copy(signature)

        manifest_buf = (ctypes.c_char * (manifest_length + sig_length))()
        ctypes.memset(manifest_buf, 0, manifest_length + sig_length)
        ctypes.memmove(ctypes.byref(manifest_buf, manifest_length), ctypes.addressof(signature_buf),
            signature_buf_len)
    else:
        manifest_buf = (ctypes.c_char * (manifest_length))()

    out_dir = os.path.dirname(os.path.abspath(output_filename))
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)

    with open(output_filename, 'wb') as fh:
        ctypes.memmove(ctypes.byref(manifest_buf), ctypes.addressof(manifest), manifest_length)
        fh.write(manifest_buf)

def generate_manifest_toc_header (fw_id_list, hash_type, bypass):
    """
    Create a manifest table of contents header

    :param fw_id_list: List of FW elements that have different IDs
    :param hash_type: Hash to be used
    :param bypass: flag indicating if bypass PFM

    :return Instance of a manifest table of contents header
    """

    entries = 1

    if hash_type is None or hash_type > 2:
        raise ValueError ("Invalid manifest hash type: {0}".format(255 if hash_type is None else hash_type))

    if not bypass:
        entries += 1

        for count in fw_id_list.values():
            entries += (count + 1)

    return manifest_toc_header(entries, entries, hash_type, 0)

def generate_hash (hash_element_instance, hash_algo):

    # Copy the element instance to a bytearray. Passing hash_element_instance directly to the hash API
    # gives TypeError: Object type <class > cannot be passed to C code.
    element_size = ctypes.sizeof(hash_element_instance)
    element_buf = (ctypes.c_ubyte * element_size)()
    ctypes.memmove(ctypes.addressof(element_buf), ctypes.addressof(hash_element_instance), element_size)

    hash_object = hash_algo.new(element_buf)
    hash_buf = (ctypes.c_ubyte * hash_object.digest_size).from_buffer_copy(hash_object.digest())

    return hash_buf

def generate_manifest_toc (manifest_header_len, toc_header, platform_id_element, flash_device_element,
    fw_id_element_list, fw_id_list, allowable_fw_list, hash_type):
    """
    Create a manifest table of contents

    :param manifest_header_len: Length of the manifest header
    :param toc_header: Table of contents header
    :platform_id_element_len: Platform ID header instance
    :flash_device_header_len: Flash device header instance
    :param fw_id_list: List of FW with different FW IDs
    :param hash_type: Hash to be used

    :return List of a manifest table of contents instances
    """
    toc_elements_list = []
    toc_elements_hash_list = []
    hash_id = 0
    hash_len = None

    if hash_type == 2:
        hash_algo = SHA512
        hash_len = 64
    elif hash_type == 1:
        hash_algo = SHA384
        hash_len = 48
    elif hash_type == 0:
        hash_algo = SHA256
        hash_len = 32
    else:
        raise ValueError ("Invalid manifest hash type: {0}".format (hash_type))

    offset = manifest_header_len + ctypes.sizeof(toc_header) + (toc_header.entry_count * ctypes.sizeof(manifest_toc_element)) + \
        (hash_len * (toc_header.hash_count + 1))

    platform_id_entry = manifest_toc_element(PFM_V2_PLATFORM_TYPE_ID, PFM_V2_TOP_ELEMENT, 1, hash_id, offset,
        ctypes.sizeof(platform_id_element))
    toc_elements_list.append(platform_id_entry)
    hash_id += 1
    offset += platform_id_entry.length

    toc_elements_hash_list.append(generate_hash(platform_id_element, hash_algo))

    if flash_device_element is not None:
        flash_device_entry = manifest_toc_element(PFM_V2_FLASH_DEVICE_TYPE_ID, PFM_V2_TOP_ELEMENT, 0, hash_id, offset,
            ctypes.sizeof(flash_device_element))
        toc_elements_list.append(flash_device_entry)
        hash_id += 1
        offset += flash_device_entry.length

        toc_elements_hash_list.append(generate_hash(flash_device_element, hash_algo))

        for fw_type, count in fw_id_list.items():
            fw_id_entry = manifest_toc_element(PFM_V2_FW_TYPE_ID, PFM_V2_TOP_ELEMENT, 1, hash_id, offset,
                ctypes.sizeof(fw_id_element_list[fw_type]))
            toc_elements_list.append(fw_id_entry)

            hash_id += 1
            offset += fw_id_entry.length

            toc_elements_hash_list.append(generate_hash(fw_id_element_list[fw_type], hash_algo))

            fw_list = allowable_fw_list.get(fw_type)
            for num in range(0, count):
                fw_version_element = manifest_toc_element(PFM_V2_FW_VERSION_TYPE_ID, PFM_V2_FW_TYPE_ID, 1, hash_id, offset,
                    ctypes.sizeof(fw_list[num]))
                toc_elements_list.append(fw_version_element)
                hash_id += 1
                offset += fw_version_element.length
                toc_elements_hash_list.append(generate_hash(fw_list[num], hash_algo))

    return toc_elements_list, toc_elements_hash_list, hash_len

def generate_platform_info(platform_id_header, platform_id):
    """
    Create the platform information section of the manifest.

    :param platform_id_header: ID header for the platform
    :param platform_id: ID for the platform

    :return Platform manifest section
    """

    header_buf = (ctypes.c_ubyte * ctypes.sizeof(platform_id_header)).from_buffer_copy(platform_id_header)

    num_alignment = platform_id_header.id_length  % 4
    num_alignment = 0 if (num_alignment == 0) else (4 - num_alignment)
    alignment_buf = (ctypes.c_ubyte * num_alignment)()
    ctypes.memset(alignment_buf, 0, num_alignment)

    class manifest_platform_id(ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('header', ctypes.c_ubyte * ctypes.sizeof(platform_id_header)),
                    ('platform_id', ctypes.c_char * len(platform_id)),
                    ('alignment', ctypes.c_ubyte * num_alignment)]

    platform = manifest_platform_id(header_buf, platform_id, alignment_buf)

    return platform

def get_platform_id(xml_list):
    """
    Determine the platform ID for the manifest

    :param xml_list: List of parse XML files with version information.

    :return The platform ID
    """

    platform_id = None
    for filename, xml in xml_list.items():
        if "platform_id" not in xml:
            raise KeyError("Failed to generate PFM: XML has no platform id - {0}".format(filename))

        if platform_id:
            if platform_id != xml["platform_id"]:
                raise ValueError("Failed to generate PFM: Version platform ids don't match - ({0}, {1})"
                    .format(platform_id, xml["platform_id"]))
        else:
            platform_id = xml["platform_id"]

    if len(platform_id) > 255:
        raise ValueError("Failed to generate PFM: Invalid platform id length - ({0})"
            .format(len(platform_id)))

    return platform_id