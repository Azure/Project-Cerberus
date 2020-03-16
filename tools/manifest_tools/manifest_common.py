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
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import manifest_types
import manifest_parser


PFM_MAGIC_NUM = int("0x504D", 16)
CFM_MAGIC_NUM = int("0xA592", 16)
PCD_MAGIC_NUM = int("0x8EBC", 16)


class manifest_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('length', ctypes.c_ushort),
                ('magic', ctypes.c_ushort),
                ('id', ctypes.c_uint),
                ('sig_length', ctypes.c_ushort),
                ('reserved', ctypes.c_ushort)]



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
        elif string.startswith("Key"):
            config["prv_key_path"] = string.split("=")[-1].strip()
        else:
            config["xml_list"].append(string)

    return config

def load_key(key_size, prv_key_path):
    """
    Load private RSA key to sign manifest from provided path. If no valid key can be imported,
    key size will be what is provided. Otherwise, key size will be size of key imported

    :param key_size: Provided key_size
    :param prv_key_path: Provided private key path

    :return <Sign manifest or not> <key_size> <Key to use for signing>
    """

    if prv_key_path:
        try:
            key = RSA.importKey(open(prv_key_path).read())
        except Exception:
            print("Unsigned PFM will be generated, provided RSA key could not be imported: {0}".format(prv_key_path))
            traceback.print_exc ()
            return False, key_size, None

        return True, int((key.size() + 1)/8), key
    else:
        print("No RSA private key provided in config, unsigned PFM will be generated.")
        return False, key_size, None

def generate_manifest_header(manifest_id, key_size, manifest_type):
    """
    Create a manifest header

    :param manifest_id: Manifest id
    :param key_size: Size of RSA key
    :param manifest_type: Manifest type

    :return Instance of a manifest header
    """

    if manifest_type == manifest_types.PFM:
        magic_num = PFM_MAGIC_NUM
    elif manifest_type == manifest_types.CFM:
        magic_num = CFM_MAGIC_NUM
    elif manifest_type == manifest_types.PCD:
        magic_num = PCD_MAGIC_NUM
    else:
        raise ValueError ("Unknown manifest type: {0}".format (manifest_type))

    sig_len = 0 if key_size is None else key_size

    return manifest_header(0, magic_num, int(manifest_id), sig_len, 0)

def load_xmls (config_filename, max_num_xmls, xml_type):
    """
    Load XMLs listed in config file

    :param config_filename: Path to config file
    :param max_num_xmls: Maximum number of XMLs that can be loaded, set to NULL if no limit
    :param xml_type: Type of XML

    :return list of XML elements, boolean indicating whether to sign output or not, key size, 
        key to use for signing, output ID, output filename
    """

    config = load_config (config_filename)
    key_size = None
    prv_key_path = None
    sign = False

    if "key_size" in config and config["key_size"]:
        key_size = int (config["key_size"])

    if "prv_key_path" in config and config["prv_key_path"]:
        prv_key_path = config["prv_key_path"]

    if max_num_xmls and (len (config["xml_list"]) > max_num_xmls):
        raise RuntimeError ("Too many XML files provided: {0}".format (len (config["xml_list"])))

    sign, key_size, key = load_key (key_size, prv_key_path)

    processed_xml = {}

    for xml in config["xml_list"]:
        parsed_xml = manifest_parser.load_and_process_xml (xml, xml_type)

        if parsed_xml is None:
            raise RuntimeError ("Failed to parse XML: {0}".format(xml))

        processed_xml.update({xml:parsed_xml})
    
    return processed_xml, sign, key_size, key, config["id"], config["output"]

def write_manifest(sign, manifest, key, output_filename, manifest_length, sig_length):
    """
    Write manifest generated to provided path.

    :param sign: Boolean indicating whether to sign manifest or not
    :param manifest: Generated manifest to write
    :param key: Key to use for signing
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

    if sign:
        h = SHA256.new(manifest)
        signer = PKCS1_v1_5.new(key)
        signature = signer.sign(h)
        signature = (ctypes.c_ubyte * sig_length).from_buffer_copy(signature)

        manifest_buf = (ctypes.c_char * (manifest_length + sig_length))()
        ctypes.memmove(ctypes.byref(manifest_buf, manifest_length), ctypes.addressof(signature),
                           sig_length)
    else:
        manifest_buf = (ctypes.c_char * (manifest_length))()

    out_dir = os.path.dirname(os.path.abspath(output_filename))
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)

    with open(output_filename, 'wb') as fh:
        ctypes.memmove(ctypes.byref(manifest_buf), ctypes.addressof(manifest), manifest_length)
        fh.write(manifest_buf)
