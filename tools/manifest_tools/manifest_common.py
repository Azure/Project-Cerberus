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


PFM_MAGIC_NUM = int ("0x504D", 16)
CFM_MAGIC_NUM = int ("0xA592", 16)
PCD_MAGIC_NUM = int ("0x1029", 16)

PFM_V2_MAGIC_NUM = int ("0x706D", 16)

V2_BASE_TYPE_ID = int ("0xff", 16)
V2_PLATFORM_TYPE_ID = int ("0x00", 16)

PFM_V2_FLASH_DEVICE_TYPE_ID = int ("0x10", 16)
PFM_V2_FW_TYPE_ID = int ("0x11", 16)
PFM_V2_FW_VERSION_TYPE_ID = int ("0x12", 16)

PCD_V2_ROT_TYPE_ID = int ("0x40", 16)
PCD_V2_I2C_CPLD_TYPE_ID = int ("0x41", 16)
PCD_V2_DIRECT_COMPONENT_TYPE_ID = int ("0x42", 16)
PCD_V2_MCTP_BRIDGE_COMPONENT_TYPE_ID = int ("0x43", 16)

class manifest_header (ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('length', ctypes.c_ushort),
                ('magic', ctypes.c_ushort),
                ('id', ctypes.c_uint),
                ('sig_length', ctypes.c_ushort),
                ('sig_type', ctypes.c_ubyte),
                ('reserved', ctypes.c_ubyte)]

class manifest_toc_header (ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('entry_count', ctypes.c_ubyte),
                ('hash_count', ctypes.c_ubyte),
                ('hash_type', ctypes.c_ubyte),
                ('reserved', ctypes.c_ubyte)]

class manifest_toc_entry (ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('type_id', ctypes.c_ubyte),
                ('parent', ctypes.c_ubyte),
                ('format', ctypes.c_ubyte),
                ('hash_id', ctypes.c_ubyte),
                ('offset', ctypes.c_ushort),
                ('length', ctypes.c_ushort)]


def get_key_from_dict (dictionary, key, group, required=True):
    """
    Grab a value from dictionary

    :param dictionary: Dictionary to utilize
    :param key: Key to fetch
    :param group: Group this key belongs to, used for error reporting purposes
    :param required: Boolean indicating whether this key is necessary for a valid manifest

    :return Value if found
    """

    if key not in dictionary:
        if required:
            raise KeyError ("Failed to generate manifest: {0} missing {1}".format (group, key))
        else:
            return None
    else:
        return dictionary[key]

def load_config (config_file):
    """
    Load configuration options from file

    :param config_file: Path for a text file containing config options

    :return Parsed configuration
    """

    config = {}
    config["xml_list"] = []
    config["prv_key_path"] = ""
    config["output"] = ""
    config["key_size"] = ""
    config["hash_type"] = ""
    config["key_type"] = ""

    with open (config_file, 'r') as fh:
        data = fh.readlines ()

    if not data:
        raise IOError ("Could not load configuration file: {0}".format (config_file))

    for string in data:
        string = string.replace ("\n", "")
        string = string.replace ("\r", "")

        if string.startswith ("ID"):
            config["id"] = string.split ("=")[-1].strip ()
        elif string.startswith ("Output"):
            config["output"] = string.split ("=")[-1].strip ()
        elif string.startswith ("KeySize"):
            config["key_size"] = string.split ("=")[-1].strip ()
        elif string.startswith ("KeyType"):
            config["key_type"] = string.split ("=")[-1].strip ()
        elif string.startswith ("HashType"):
            config["hash_type"] = string.split ("=")[-1].strip ()
        elif string.startswith ("Key"):
            config["prv_key_path"] = string.split ("=")[-1].strip ()
        else:
            config["xml_list"].append (string)

    return config

def load_key (key_type, key_size, prv_key_path):
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
                key = ECC.import_key (open (prv_key_path).read())
                keysize = int (key.pointQ.size_in_bytes ())
            else:
                key = RSA.importKey (open (prv_key_path).read())
                keysize = int (key.n.bit_length ()/8)

        except Exception:
            raise IOError ("Provided {0} key could not be imported: {1}".format (
                "ECC" if key_type == 1 else "RSA", prv_key_path))

        return True, keysize, key
    else:
        print ("No RSA private key provided in config, unsigned PFM will be generated.")
        return False, key_size, None

def generate_manifest_header (manifest_id, key_size, manifest_type, hash_type, key_type, 
    manifest_version):
    """
    Create a manifest header

    :param manifest_id: Manifest id
    :param key_size: Size of signing key, optional
    :param manifest_type: Manifest type
    :param hash_type: Hashing algorithm
    :param key_type: Signing key algorithm, optional 
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

    return manifest_header (0, magic_num, int (manifest_id), sig_len, sig_type, 0)

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
        if config["hash_type"] == "SHA512":
            hash_type = 2
        elif config["hash_type"] == "SHA384":
            hash_type = 1
        else:
            hash_type = 0
    
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
        parsed_xml, curr_xml_version = manifest_parser.load_and_process_xml (xml, xml_type)

        if parsed_xml is None:
            raise RuntimeError ("Failed to parse XML: {0}".format (xml))
        else:
            if xml_version is None:
                xml_version = curr_xml_version

            if xml_version != curr_xml_version:
                raise RuntimeError (
                    "Failed to generate PFM: XML version is different - {0}".format (xml))

        processed_xml.update ({xml:parsed_xml})

    if "id" in config:
        manifest_id = config["id"]
    else:
        manifest_id = list (processed_xml.items())[0][1]["version"]

    return processed_xml, sign, key_size, key, key_type, hash_type, manifest_id, config["output"], \
        xml_version

def write_manifest (xml_version, sign, manifest, key, key_size, key_type, output_filename,
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

    if ctypes.sizeof (manifest) > (65535 - sig_length):
        raise ValueError ("Manifest is too large - {0}".format (ctypes.sizeof (manifest)))

    if ctypes.sizeof (manifest) != manifest_length:
        raise ValueError ("Manifest doesn't match output size")

    if key_type > 1:
        raise ValueError ("Manifest Signing key type is not set correctly")

    sha_algo = SHA512 if key_size == 512 else SHA384 if key_size == 384 else SHA256

    if xml_version == manifest_types.VERSION_1 and key_type == 1:
        raise ValueError ("Manifest Signing key type not supported for version 1 xml")

    if sign:
        manifest_hash_buf = (ctypes.c_ubyte * manifest_length)()
        ctypes.memmove (ctypes.addressof (manifest_hash_buf), ctypes.addressof (manifest), 
            manifest_length)
        h = sha_algo.new(manifest_hash_buf)

        if key_type == 1:
            signer = DSS.new(key, 'fips-186-3', 'der')
        else:
            signer = PKCS1_v1_5.new(key)

        signature = signer.sign (h)
        signature_buf_len = len (signature) if len (signature) < sig_length else sig_length
        signature_buf = (ctypes.c_ubyte * signature_buf_len).from_buffer_copy (signature)

        manifest_buf = (ctypes.c_char * (manifest_length + sig_length))()
        ctypes.memset (manifest_buf, 0, manifest_length + sig_length)
        ctypes.memmove (ctypes.byref (manifest_buf, manifest_length), 
            ctypes.addressof (signature_buf), signature_buf_len)
    else:
        manifest_buf = (ctypes.c_char * (manifest_length)) ()

    out_dir = os.path.dirname (os.path.abspath (output_filename))
    if not os.path.exists (out_dir):
        os.makedirs (out_dir)

    with open (output_filename, 'wb') as fh:
        ctypes.memmove (ctypes.byref (manifest_buf), ctypes.addressof (manifest), manifest_length)
        fh.write (manifest_buf)

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
        raise ValueError ("Invalid manifest hash type: {0}".format (hash_type))

    if not bypass:
        entries += 1

        for count in fw_id_list.values ():
            entries += (count + 1)

    return manifest_toc_header (entries, entries, hash_type, 0)

def generate_hash (element, hash_engine):
    """
    Generate hash of a ctypes element

    :param element: Element to hash
    :param hash_engine: Hashing engine to utilize

    :return Buffer with digest
    """

    # Copy the element instance to a bytearray. Passing element directly to the hash API
    # gives TypeError: Object type <class > cannot be passed to C code.
    element_size = ctypes.sizeof (element)
    element_buf = (ctypes.c_ubyte * element_size) ()
    
    ctypes.memmove (ctypes.addressof (element_buf), ctypes.addressof (element), element_size)

    hash_object = hash_engine.new (element_buf)
    hash_buf = (ctypes.c_ubyte * hash_object.digest_size).from_buffer_copy (hash_object.digest ())

    return hash_buf

def generate_platform_info (platform_id_header, platform_id):
    """
    Create the platform information section of the manifest.

    :param platform_id_header: ID header for the platform
    :param platform_id: ID for the platform

    :return Platform manifest section
    """

    header_buf = (ctypes.c_ubyte * ctypes.sizeof (platform_id_header)).from_buffer_copy (
        platform_id_header)

    num_alignment = platform_id_header.id_length  % 4
    num_alignment = 0 if (num_alignment == 0) else (4 - num_alignment)
    alignment_buf = (ctypes.c_ubyte * num_alignment) ()
    ctypes.memset (alignment_buf, 0, num_alignment)

    class manifest_platform_id(ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('header', ctypes.c_ubyte * ctypes.sizeof (platform_id_header)),
                    ('platform_id', ctypes.c_char * len (platform_id)),
                    ('alignment', ctypes.c_ubyte * num_alignment)]

    platform = manifest_platform_id (header_buf, platform_id, alignment_buf)

    return platform

def get_platform_id (xml_list):
    """
    Determine the platform ID for the manifest

    :param xml_list: List of parse XML files with version information.

    :return The platform ID
    """

    platform_id = None
    for filename, xml in xml_list.items ():
        if "platform_id" not in xml:
            raise KeyError ("Failed to generate PFM: XML has no platform id - {0}".format (
                filename))

        if platform_id:
            if platform_id != xml["platform_id"]:
                raise ValueError (
                    "Failed to generate PFM: Version platform ids don't match - ({0}, {1})"
                    .format(platform_id, xml["platform_id"]))
        else:
            platform_id = xml["platform_id"]

    if len (platform_id) > 255:
        raise ValueError ("Failed to generate PFM: Invalid platform id length - ({0})"
            .format (len (platform_id)))

    return platform_id

def get_hash_engine (hash_type):
    """
    Initialize a hash engine instance.

    :param hash_type: Hashing algorithm to use

    :return Hash engine object
    """

    if hash_type == 0:
        hash_engine = SHA256
    elif hash_type == 1:
        hash_engine = SHA384
    elif hash_type == 2:
        hash_engine = SHA512
    else:
        raise ValueError ("Invalid manifest hash type: {0}".format (hash_type))

    return hash_engine

def generate_platform_id_buf (xml_platform_id, hash_engine):
    """
    Create a platform ID object from parsed XML list

    :param xml_platform_id: List of parsed XML of platform id to be included in the object
    :param hash_engine: Hashing engine

    :return Instance of a platform ID object, object's TOC entry, object hash
    """

    platform_id_str = get_key_from_dict (xml_platform_id, "platform_id", "Platform ID")

    platform_id_str_len = len (platform_id_str)

    padding_len = ((platform_id_str_len + 3) & (~3)) - platform_id_str_len
    padding = (ctypes.c_ubyte * padding_len) ()
    ctypes.memset (padding, 0, ctypes.sizeof (ctypes.c_ubyte) * padding_len)

    reserved = (ctypes.c_ubyte * 3) ()
    ctypes.memset (reserved, 0, ctypes.sizeof (ctypes.c_ubyte) * 3)

    class pcd_platform_id_element (ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('platform_id_length', ctypes.c_ubyte),
                    ('reserved', ctypes.c_ubyte * 3),
                    ('platform_id', ctypes.c_char * platform_id_str_len),
                    ('platform_id_padding', ctypes.c_ubyte * padding_len)]

    platform_id = pcd_platform_id_element (platform_id_str_len, reserved, 
        platform_id_str.encode ('utf-8'), padding)
    platform_id_len = ctypes.sizeof (platform_id)

    platform_id_toc_entry = manifest_toc_entry (V2_PLATFORM_TYPE_ID, V2_BASE_TYPE_ID, 1, 0, 0, 
        platform_id_len)

    platform_id_hash = generate_hash (platform_id, hash_engine)

    return platform_id, platform_id_toc_entry, platform_id_hash

def generate_toc (hash_engine, hash_type, toc_list, hash_list):
    """
    Create manifest table of contents from list of pregenerated TOC entries and hash list for all 
    elements

    :param hash_engine: Hashing engine
    :param hash_type: Hashing algorithm
    :param toc_list: List of TOC entries to be included in the TOC
    :param hash_list: List of hashes for all elements in manifest. Hash list ordering must match 
        toc_list's

    :return TOC buffer
    """

    if len (toc_list) != len (hash_list):
        raise ValueError ("toc_list and hash_list lengths dont match: {0} vs {1}".format (
            len (toc_list), len (hash_list)))

    num_entries = len (toc_list)
    hash_len = hash_engine.digest_size 

    toc_len = ctypes.sizeof (manifest_toc_header) + \
        (ctypes.sizeof (manifest_toc_entry) * num_entries) + ((num_entries + 1) * hash_len)
    toc = (ctypes.c_ubyte * toc_len) ()

    toc_header_len = ctypes.sizeof (manifest_toc_header)
    toc_header = manifest_toc_header (num_entries, num_entries, hash_type, 0)
    ctypes.memmove (ctypes.addressof (toc), ctypes.addressof (toc_header), toc_header_len)

    offset = ctypes.sizeof (manifest_header) + toc_len
    hash_id = 0
    toc_entry_len = ctypes.sizeof (manifest_toc_entry)
    toc_offset = toc_header_len

    for entry in toc_list:
        entry.offset = offset
        offset += entry.length

        entry.hash_id = hash_id
        hash_id += 1

        ctypes.memmove (ctypes.addressof (toc) + toc_offset, ctypes.addressof (entry), 
            toc_entry_len)
        toc_offset += toc_entry_len

    for hash_entry in hash_list:
        ctypes.memmove (ctypes.addressof (toc) + toc_offset, ctypes.addressof (hash_entry), 
            hash_len)
        toc_offset += hash_len

    table_hash = generate_hash (toc, hash_engine)
    ctypes.memmove (ctypes.addressof (toc) + toc_offset, ctypes.addressof (table_hash), hash_len)

    return toc
