#!/usr/bin/python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Usage:
#  spdm_measurements_to_cfm.py <component_name> <input_filename> <optional params>
#  Optional Params:
#   -l <get_comp_list>
#   -f <comp_def_file>
#   -c <comp_filter_file>
#   -d <debug> [Debug Param(Provides debug logs)]
#  E.g.
#   spdm_measurements_to_cfm.py <comp_name> spdm_measurement.corim -l
#   spdm_measurements_to_cfm.py <comp_name> spdm_measurement.rim -c <model_name>_auto_gen_comp_filter.cfg
#   spdm_measurements_to_cfm.py <comp_name> spdm_measurement.rim -c <model_name>_auto_gen_comp_filter.cfg -f <path to component_defaults.cfg file>
#  Notes:
#   1. All other parameters required to run the script will be read from component_defaults.cfg file.
#   2. -l/--get_comp_list option cannot be used together with -c/--comp_filter_file option.
#   3. Include and Exclude List both cannot be used together. Meaning, config filter file must
#      have either Include List or Exclude List defined. Otherwise, warning will be generated.
#   4. Below is the Template to create components_defaults.cfg file. Do not change Defaults.
#      Keep a single entry for each component_name.
#      [Defaults]
#        output_filename: output_files/cfm_component.xml
#        workspace_dir: workspace
#        slot_num: 0
#      [component_name]
#        base_hash_algo: <Algorithm name ex: SHA384>
#        measure_hash_algo: <Algorithm name ex: SHA384>
#        rootca_digest_val: <RootCA Digest>
#        signed_flag: <True/False>
#        file_type: <CORIM/RIM>
#  How to run:
#   1. First generate component filter file using -l option. Output file will contain all the supported
#      sub-components, which will be by default part of Include List.
#   2. Check if you want to use default generated file as is i.e., generate XML for all the sub-components.
#      If not, then make changes in either Include or Exclude List.
#   3. Input the generated file to the script using -c option. Script will parse the config file and generate
#      XML files.

# TODO: Replace shell commands with python file system APIs

import os
import sys
import copy
import enum
import argparse
import json as js
import xml.etree.ElementTree as et
from enum import Enum
import base64
import warnings
import configparser

#globals
smc_component_name="component"
smc_input_filename="spdm_measurement.rim"
smc_output_filename="cfm_component.xml"
smc_comp_filter_cfg_filename="cfm_xml_comp_filter.cfg"
smc_auto_gen_comp_filter_cfg_filename="auto_gen_comp_filter.cfg"
smc_comp_def_cfg_filename="component_defaults.cfg"
smc_filetype="RIM"
smc_slot_num="0"
smc_rootca_digest=""
smc_base_hash_alg="SHA384"
smc_meas_hash_alg="SHA384"
smc_signed_flag=True
smc_ws_dir="."
smc_output_dir=""
smc_debug=False
smc_get_comp_list=False
smc_component_inc_list=[]
smc_component_exc_list=[]

#filetypes
CONFIG_TYPE_RIM="RIM"
CONFIG_TYPE_CORIM="CORIM"

#RIM format tags
CONFIG_TAG_MEASUREMENT_RECORDS="measurement records"
CONFIG_TAG_TCBINFO="tcbinfo"
CONFIG_TAG_COMMENT="//"
CONFIG_TAG_VENDOR="vendor"
CONFIG_TAG_MODEL="model"
CONFIG_TAG_TYPE="type"
CONFIG_TAG_LAYER="layer"
CONFIG_TAG_FWIDS="fwids"
CONFIG_TAG_HASH_ALG="hashAlg"
CONFIG_TAG_DIGEST="digest"
CONFIG_TAG_VENDOR_INFO="vendorInfo"
CONFIG_TAG_VENDOR_INFO_MASK="vendorInfoMask"
CONFIG_TAG_RAW_VALUE="raw-value"
CONFIG_TAG_DIGESTS="digests"

#CORIM format tags
CONFIG_TAG_IDENTITY="tag-identity"
CONFIG_TAG_ENTITIES="entities"
CONFIG_TAG_ID="id"
CONFIG_TAG_NAME="name"
CONFIG_TAG_REGID="regid"
CONFIG_TAG_ROLES="roles"
CONFIG_TAG_TRIPLES="triples"
CONFIG_TAG_REFERNCE_VAUES="reference-values"
CONFIG_TAG_ENVIRONMENT="environment"
CONFIG_TAG_CLASS="class"
CONFIG_TAG_VENDOR="vendor"
CONFIG_TAG_MODEL="model"
CONFIG_TAG_MEASUREMENTS="measurements"
CONFIG_TAG_KEY="key"
CONFIG_TAG_TYPE="type"
CONFIG_TAG_VALUE="value"
CONFIG_TAG_RAW_VALUE="raw-value"
CONFIG_TAG_RAW_VALUE_MASK="raw-value-mask"
CONFIG_TAG_DIGESTS="digests"
CONFIG_TAG_DIGEST_SHA384="sha-384"

#CFM format strings
CONFIG_STR_CFM_COMPONENT="CFMComponent"
CONFIG_STR_TYPE="type"
CONFIG_STR_ATTESTATION_PROTOCOL="attestation_protocol"
CONFIG_STR_SLOT_NUM="slot_num"
CONFIG_STR_TRANSCRIPT_HASH_TYPE="transcript_hash_type"
CONFIG_STR_MEASUREMENT_HASH_TYPE="measurement_hash_type"
CONFIG_STR_ROOTCA_DIGEST="RootCADigest"
CONFIG_STR_DIGEST="Digest"
CONFIG_STR_MEASUREMENT_DATA="MeasurementData"
CONFIG_STR_PMR_ID="pmr_id"
CONFIG_STR_MEASUREMENT_ID="measurement_id"
CONFIG_STR_ALLOWABLE_DATA="AllowableData"
CONFIG_STR_ENDIANESS="Endianness"
CONFIG_STR_CHECK="Check"
CONFIG_STR_DATA="Data"
CONFIG_STR_BTMASK="Bitmask"
CONFIG_STR_MEASUREMENT="Measurement"

#CFM format values
CONFIG_VALUE_ATTESTATION_PROTOCOL_SPDM="SPDM"
CONFIG_VALUE_ENDIANESS_BIG_ENDIAN="BigEndian"
CONFIG_VALUE_CHECK_EQUAL="Equal"
CONFIG_VALUE_TRANSCRIPT_HASH_TYPE_SHA384="SHA384"
CONFIG_VALUE_MEASUREMENT_HASH_TYPE_SHA384="SHA384"

#Component Map Config Sections and Keys/Values
COMPONENT_MAP_DEFAULTS_SECTION='Defaults'
COMPONENT_MAP_DEFAULT_OUTPUT_FILENAME='output_filename'
COMPONENT_MAP_DEFAULT_WORKSPACE_DIR='workspace_dir'
COMPONENT_MAP_DEFAULT_SLOT_NUM='slot_num'
COMPONENT_MAP_BASE_HASH_ALGO='base_hash_algo'
COMPONENT_MAP_MEASURE_HASH_ALGO='measure_hash_algo'
COMPONENT_MAP_ROOTCA_DIGEST_VAL='rootca_digest_val'
COMPONENT_MAP_SIGNED_FLAG='signed_flag'
COMPONENT_MAP_FILE_TYPE='file_type'

## helpers functions to create the cfm xml file
# python 3.9 and above has this function already implemented
def indent(elem, level=0):
    """
    Indents a CFM file (required for python < v3.9).

    :param elem: Root of the element tree
    :param level: Level to perform identation, default value 0
    """
    i = "\n" + level*"\t"
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "\t"
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
        for elem in elem:
            indent(elem, level+1)
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = i

def is_not_blank(s):
    return bool(s and not s.isspace())

class Measurement_Type(Enum):
    """
    Enum for measurement type, UINT and DIGEST are supported.
    """
    CONFIG_TYPE_UNKNOWN = 0
    CONFIG_TYPE_UINT = 1
    CONFIG_TYPE_DIGEST = 2

class Rim_Measurement:
    def __init__(self, idx, type, subtype, value, mask):
        """
        Represents RIM format specific measurement.

        :param idx: Measurement index
        :param type: Measurement type, identified using Measurement_Type Enum
        :param subtype: Measurement subtype (raw-value, digests)
        :param value: Measurement value
        :param mask: Measurement mask for measurement value
        """
        self.id = idx
        self.type =  type
        self.subtype = subtype
        self.value = value
        self.mask = mask

    def __str__(self):
        """
        :return String format of the object.
        """
        return f'id = {self.id}, type = {self.type}, subtype = {self.subtype}, value = {self.value}, mask = {self.mask}'

class Rim_Data:
    def __init__(self, filename, output_filename, config):
        """
        Represents RIM data and configuration

        :param filename: Input filename
        :param output_filename: Output filename
        :param: config: RIM configuration data
        """
        self.filename = filename
        self.output_filename = output_filename
        self.slot_num = config.slot_num
        self.rootca_digest = config.rootca_digest
        self.base_hash_alg = config.base_hash_alg
        self.meas_hash_alg = config.meas_hash_alg
        self.model = ""
        self.measurements = []

    def parse_json_file(self):
        """
        Parses the json file and stores the measurements in RIM data
        """
        self.measurements = []

        with open(self.filename, "r") as json_file:
            data = js.load(json_file);
            tag_tcbinfo = data[CONFIG_TAG_MEASUREMENT_RECORDS][CONFIG_TAG_TCBINFO]
            for d in tag_tcbinfo:
                if d[CONFIG_TAG_LAYER] == '0' and CONFIG_TAG_MODEL in d:
                        self.model = d[CONFIG_TAG_MODEL]
                elif d[CONFIG_TAG_LAYER] == '2':
                    if CONFIG_TAG_FWIDS in d:
                        tag_fwids = d[CONFIG_TAG_FWIDS][0]
                        measurement = Rim_Measurement(len(self.measurements) + 1, Measurement_Type.CONFIG_TYPE_DIGEST, CONFIG_TAG_DIGESTS, tag_fwids[CONFIG_TAG_DIGEST], None)
                        self.measurements.append(measurement)
                    elif CONFIG_TAG_VENDOR_INFO in d:
                        measurement = Rim_Measurement(len(self.measurements) + 1, Measurement_Type.CONFIG_TYPE_UINT, CONFIG_TAG_RAW_VALUE, d[CONFIG_TAG_VENDOR_INFO], d[CONFIG_TAG_VENDOR_INFO_MASK])
                        self.measurements.append(measurement)


    def display(self):
        """
        Displays the RIM data
        """
        print ("=================================================================================")
        print ("CFM processed. input_filename=", self.filename)
        print ("=================================================================================")
        print ("Model=", self.model)
        print ("Slot Num=", self.slot_num)
        print ("RootCA Digest=", self.rootca_digest)
        print ("Base Hash Alg=", self.base_hash_alg)
        print ("Meas Hash Alg=", self.meas_hash_alg)
        if (smc_debug == True):
            print ("Measurements:=")
            for measurement in self.measurements:
                print (measurement)
        print ("=================================================================================")

class Corim_Measurement:
    def __init__(self, idx, type, subtype, value, mask):
        """
        Represents CORIM format specific measurement.

        :param idx: Measurement index
        :param type: Measurement type, identified using Measurement_Type Enum
        :param subtype: Measurement subtype (raw-value, digests)
        :param value: Measurement value
        :param mask: Measurement mask for measurement value
        """
        self.id = idx
        self.type =  type
        self.subtype = subtype
        self.value = value
        self.mask = mask

    def __str__(self):
        """
        :return String format of the object.
        """
        return f'id = {self.id}, type = {self.type}, subtype = {self.subtype}, value = {self.value}, mask = {self.mask}'

class Corim_Data:
    def __init__(self, filetype, filename, output_filename, config):
        """
        Represents CORIM data and configuration

        :param filename: Input filename
        :param output_filename: Output filename
        :param: config: CORIM configuration data
        """
        self.filetype = filetype
        self.filename = filename
        self.id = 0
        self.name = "UNKNOWN"
        self.regid = 0
        self.roles = []
        self.vendor = ""
        self.model = ""
        self.output_filename = output_filename
        self.slot_num = config.slot_num
        self.rootca_digest = config.rootca_digest
        self.base_hash_alg = config.base_hash_alg
        self.meas_hash_alg = config.meas_hash_alg
        self.measurements = []

    def execute_command(self, cmd_str):
        """
        Executes specified shell based command

        :param cmd_str: Command to be executed
        """
        if (smc_debug == True):
            print ("cmd_str = ", cmd_str)
        os.system(cmd_str)

    def set_vendor_model_name(self, tag_environment):
        """
        Set self.model to vendor provided model name.
        """
        if CONFIG_TAG_MODEL in tag_environment[CONFIG_TAG_CLASS]:
            self.model = tag_environment[CONFIG_TAG_CLASS][CONFIG_TAG_MODEL]
            self.model = self.model.upper()
            if smc_component_name in self.model:
                self.model = smc_component_name
            elif ' ' in self.model:
                self.model = self.model.split(' ', 1)[0]

    def get_model_name(self, tag_measurements):
        """
        Get model name from tag measurements.
        """
        value = ""
        for d in tag_measurements:
            if CONFIG_TAG_RAW_VALUE in d[CONFIG_TAG_VALUE]:
                if CONFIG_TAG_VALUE in d[CONFIG_TAG_VALUE][CONFIG_TAG_RAW_VALUE]:
                    value = base64.b64decode(d[CONFIG_TAG_VALUE][CONFIG_TAG_RAW_VALUE][CONFIG_TAG_VALUE])
                else:
                    value = base64.b64decode(d[CONFIG_TAG_VALUE][CONFIG_TAG_RAW_VALUE])
                if smc_component_name not in self.model:
                    if (d[CONFIG_TAG_KEY][CONFIG_TAG_VALUE] == 2):
                        encoded = value.hex().replace('00', '')
                        if (is_not_blank(bytearray.fromhex(encoded).decode())):
                            model = bytearray.fromhex(encoded).decode()
                            return model
        return smc_component_name

    def create_json_files(self):
        """
        Creates the Json files

        :return List of JSON filenames
        """
        json_filenames = []
        self.execute_command("rm -rf " + smc_ws_dir)
        self.execute_command("mkdir " + smc_ws_dir)
        if smc_signed_flag == "True":
            self.execute_command("dd bs=1 skip=6 if=" + self.filename + " of=" + self.filename + "_untagged")
            self.execute_command("$COCLI_PATH/cocli corim extract -f " + self.filename + "_untagged" + " --output-dir=" + smc_ws_dir)
        else:
            self.execute_command("$COCLI_PATH/cocli corim extract -f " + self.filename + " --output-dir=" + smc_ws_dir)

        for filename in os.listdir(smc_ws_dir):
            if filename.endswith(".cbor"):
                json_filename = filename.split(".")[0] + ".json"
                filepath = os.path.join(smc_ws_dir, filename)
                json_filepath = os.path.join(smc_ws_dir, json_filename)
                self.execute_command("$COCLI_PATH/cocli comid display --file " + filepath + " > " + json_filepath)
                json_filenames.append(json_filepath)
                self.execute_command("sed -i '1d' " + json_filepath)

        if self.filetype == CONFIG_TYPE_CORIM:
            self.execute_command("rm -f " + self.filename + "_untagged")

        for filename in os.listdir(smc_ws_dir):
            if filename.endswith(".cbor"):
                filepath = os.path.join(smc_ws_dir, filename)
                self.execute_command("rm -f " + filepath)
        return json_filenames

    def parse_json_file(self, json_filename):
        """
        Parses the json file and stores the measurements in CORIM data
        """
        self.measurements = []

        # Opening JSON file in read mode
        with open(json_filename, "r") as json_file:

            # loading json file data to variable data
            data = js.load(json_file);

            d = data[CONFIG_TAG_IDENTITY]
            self.id = d[CONFIG_TAG_ID]

            if CONFIG_TAG_ENTITIES in data:
                d = data[CONFIG_TAG_ENTITIES][0]
                self.name = d[CONFIG_TAG_NAME]
                if (CONFIG_TAG_REGID in d):
                    self.regid = d[CONFIG_TAG_REGID]
                else:
                    self.regid = 0
                self.roles = d[CONFIG_TAG_ROLES]

            d = data[CONFIG_TAG_TRIPLES][CONFIG_TAG_REFERNCE_VAUES][0]
            tag_environment = d[CONFIG_TAG_ENVIRONMENT]

            self.vendor = tag_environment[CONFIG_TAG_CLASS][CONFIG_TAG_VENDOR]
            self.set_vendor_model_name(tag_environment)

            tag_measurements = d[CONFIG_TAG_MEASUREMENTS]

            """
            Get component/model name.
            """
            self.model = self.get_model_name(tag_measurements)

            """
            Skip component/model when -
            1. exclude_list is not empty and component/model is part of the list.
            2. include_list is not empty and component/model is not part of the list.
            """
            if (smc_component_exc_list) and (self.model in smc_component_exc_list):
                return self.measurements

            if (smc_component_inc_list) and (self.model not in smc_component_inc_list):
                return self.measurements

            print ("self.model =", self.model)

            for d in tag_measurements:
                if CONFIG_TAG_RAW_VALUE in d[CONFIG_TAG_VALUE]:
                    if CONFIG_TAG_VALUE in d[CONFIG_TAG_VALUE][CONFIG_TAG_RAW_VALUE]:
                        value = base64.b64decode(d[CONFIG_TAG_VALUE][CONFIG_TAG_RAW_VALUE][CONFIG_TAG_VALUE])
                    else:
                        value = base64.b64decode(d[CONFIG_TAG_VALUE][CONFIG_TAG_RAW_VALUE])
                    if CONFIG_TAG_RAW_VALUE_MASK in d[CONFIG_TAG_VALUE]:
                        mask = base64.b64decode(d[CONFIG_TAG_VALUE][CONFIG_TAG_RAW_VALUE_MASK]).hex()
                    else:
                        mask = format((1 << (len(value) * 8)) - 1, 'x')
                    measurement = Corim_Measurement(d[CONFIG_TAG_KEY][CONFIG_TAG_VALUE], Measurement_Type.CONFIG_TYPE_UINT,
                        CONFIG_TAG_RAW_VALUE, value.hex(), mask)
                else:
                    if ':' in d[CONFIG_TAG_VALUE][CONFIG_TAG_DIGESTS][0]:
                        value = base64.b64decode(d[CONFIG_TAG_VALUE][CONFIG_TAG_DIGESTS][0].split(':')[1]).hex()
                    else:
                        value = base64.b64decode(d[CONFIG_TAG_VALUE][CONFIG_TAG_DIGESTS][0].split(';')[1]).hex()
                    measurement = Corim_Measurement(d[CONFIG_TAG_KEY][CONFIG_TAG_VALUE], Measurement_Type.CONFIG_TYPE_DIGEST,
                        CONFIG_TAG_DIGESTS, value, None)
                self.measurements.append(measurement)
        return self.measurements

    def extract_model_name(self, json_filename):
        """
        Parses the json file to extract component/model name.
        """

        # Opening JSON file in read mode
        with open(json_filename, "r") as json_file:

            # loading json file data to variable data
            data = js.load(json_file);

            d = data[CONFIG_TAG_TRIPLES][CONFIG_TAG_REFERNCE_VAUES][0]
            tag_environment = d[CONFIG_TAG_ENVIRONMENT]
            tag_measurements = d[CONFIG_TAG_MEASUREMENTS]

            """
            Set self.model before we extract model name from CoRIM file.
            This is needed to check smc_component_name with self.model later
            when we actually extract model name. If model name is not present
            in CoRIM file, then we set smc_component_name as self.model
            """
            self.set_vendor_model_name(tag_environment)

            """
            Get component/model name.
            """
            self.model = self.get_model_name(tag_measurements)
            return self.model

        return smc_component_name

    def display(self, filename):
        """
        Displays the CORIM data
        """
        print ("=================================================================================")
        print ("CFM processed. input_filename=", filename)
        print ("=================================================================================")
        print ("ID=", self.id)
        print ("Name=", self.name)
        print ("RegId=", self.regid)
        print ("Roles=", self.roles)
        print ("Vendor=", self.vendor)
        print ("Model=", self.model)
        print ("Slot Num=", self.slot_num)
        print ("RootCA Digest=", self.rootca_digest)
        print ("Base Hash Alg=", self.base_hash_alg)
        print ("Meas Hash Alg=", self.meas_hash_alg)
        if (smc_debug == True):
            print ("Measurements:=")
            for measurement in self.measurements:
                print (measurement)
        print ("=================================================================================")


class SPDM_Measurement_Config:
    def __init__(self, slot_num, rootca_digest, base_hash_alg, meas_hash_alg):
        """
        Represents SPDM measurement configuration

        :param slot_num: Slot number
        :param rootca_digest: RootCA digest
        :param: base_hash_alg: Base Hash Algorithm
        :param: meas_hash_alg: Meas Hash Algorithm
        """
        self.slot_num = slot_num
        self.rootca_digest = rootca_digest
        self.base_hash_alg = base_hash_alg
        self.meas_hash_alg = meas_hash_alg

    def __str__(self):
        """
        Returns the string format of the object.
        """
        return f'slot_num = {self.slot_num}, rootca_digest = {self.rootca_digest},' \
            'base_hash_alg = {self.base_hash_alg}, meas_hash_alg = self.meas_hash_alg}'

class SPDM_Measurement_Data():
    def __init__(self, input_filename, output_filename, filetype, config):
        """
        Represents SPDM measurement data

        :param input_filename: Input filename
        :param output_filename: Output filename
        :param filetype: File Type (RIM/CORIM)
        :param: config: SPDM configuration
        """
        self.input_filename = input_filename
        self.output_filename = output_filename
        self.filetype = filetype
        self.config = config
        if self.filetype == CONFIG_TYPE_RIM:
            self.data = Rim_Data(input_filename, output_filename, self.config)
        elif self.filetype == CONFIG_TYPE_CORIM:
            self.data = Corim_Data(filetype, input_filename, output_filename, self.config)

    def execute_command(self, cmd_str):
        """
        Executes specified shell based command.

        :param cmd_str: Command to be executed
        """
        if (smc_debug == True):
            print ("cmd_str = ", cmd_str)
        os.system(cmd_str)

    def add_cfm_root_ca_digest(self, root, data):
        """
        Adds CFM ROOTCA Digest information.

        :param root: root for the CFM xml tree
        :param data: rootca data to be added
        """
        rootca= et.SubElement(root, CONFIG_STR_ROOTCA_DIGEST)
        digest = et.SubElement(rootca, CONFIG_STR_DIGEST)
        digest.text = self.data.rootca_digest

    def add_cfm_measurement_data(self, root, pmr_id, measurement_id, endianess_str, check_str, data_str, bitmask_str):
        """
        Adds CFM Measurement data information.

        :param root: root for the CFM xml tree
        :param pmr_id: PMR ID
        :param measurement_id: Measurement ID
        :param endianess_str: Endianess string value
        :param check_str: Check string value
        :param data_str: Data string value
        :param bitmask_str: Bitmask string value
        """
        measurement_data = et.SubElement(root, CONFIG_STR_MEASUREMENT_DATA)
        measurement_data.set(CONFIG_STR_PMR_ID, str(pmr_id))
        measurement_data.set(CONFIG_STR_MEASUREMENT_ID, str(measurement_id))
        allowable_data = et.SubElement(measurement_data, CONFIG_STR_ALLOWABLE_DATA)
        endianness = et.SubElement(allowable_data, CONFIG_STR_ENDIANESS)
        endianness.text = endianess_str
        check = et.SubElement(allowable_data, CONFIG_STR_CHECK)
        check.text = check_str
        data = et.SubElement(allowable_data, CONFIG_STR_DATA)
        data.text = data_str
        bitmask = et.SubElement(allowable_data, CONFIG_STR_BTMASK)
        bitmask.text = bitmask_str

    def add_cfm_measurement(self, root, pmr_id, measurement_id, digest_str):
        """
        Adds CFM measurement information.

        :param root: root for the CFM xml tree
        :param pmr_id: PMR ID
        :param measurement_id: Measurement ID
        :param digest_str: Digest string value
        """
        measurement = et.SubElement(root, CONFIG_STR_MEASUREMENT)
        measurement.set(CONFIG_STR_PMR_ID, str(pmr_id))
        measurement.set(CONFIG_STR_MEASUREMENT_ID, str(measurement_id))
        digest = et.SubElement(measurement, CONFIG_STR_DIGEST)
        digest.text = digest_str

    def create_cfm_file(self, data, output_filename):
        """
        Creates CFM file for parsed measurements.

        :param data: Measurement Data
        :param: output_filename: Output Filename
        """
        root = et.Element(CONFIG_STR_CFM_COMPONENT)
        if is_not_blank(data.model):
            root.set(CONFIG_STR_TYPE, data.model)
        else:
            root.set(CONFIG_STR_TYPE, smc_component_name)

        root.set(CONFIG_STR_ATTESTATION_PROTOCOL, CONFIG_VALUE_ATTESTATION_PROTOCOL_SPDM)
        root.set(CONFIG_STR_SLOT_NUM, data.slot_num)
        root.set(CONFIG_STR_TRANSCRIPT_HASH_TYPE, data.base_hash_alg)
        root.set(CONFIG_STR_MEASUREMENT_HASH_TYPE, data.meas_hash_alg)

        if (smc_rootca_digest != ""):
            self.add_cfm_root_ca_digest(root, data)

        pmr_id = 0
        measurement_id = 0

        for measurement in data.measurements:
            if measurement.type == Measurement_Type.CONFIG_TYPE_UINT:
                self.add_cfm_measurement_data(root, pmr_id, measurement.id, CONFIG_VALUE_ENDIANESS_BIG_ENDIAN, CONFIG_VALUE_CHECK_EQUAL, measurement.value, measurement.mask)

            if measurement.type == Measurement_Type.CONFIG_TYPE_DIGEST:
                self.add_cfm_measurement(root, pmr_id, measurement.id, measurement.value)

        tree = et.ElementTree(root)
        if ((sys.version_info.major == 3 and sys.version_info.minor >= 9) or sys.version_info.major > 3):
            et.indent(tree, '\t')
        else:
            indent(root)

        with open (output_filename, "wb") as out:
            tree.write(out, encoding="utf-8")

        print ("CFM generated. output_filename=", output_filename)

        if (smc_debug == True):
            print ("=================================================================================")
            with open (output_filename, "r") as out:
                print(out.read())
            print ("=================================================================================")

        print ("=================================================================================")
        print ("")

    def convert_to_cfm(self):
        """
        Converts input file to CFM file as per filetype.
        """
        self.execute_command("rm -rf " + smc_output_dir)
        self.execute_command("mkdir " + smc_output_dir)

        if self.filetype == CONFIG_TYPE_RIM:
            self.data.parse_json_file()
            self.data.display()
            if is_not_blank(self.data.model):
                self.create_cfm_file(self.data, self.output_filename.split(".")[0] + "_" + self.data.model + ".xml")
            else:
                self.create_cfm_file(self.data, self.output_filename.split(".")[0] + "_" + smc_component_name + ".xml")
        elif self.filetype == CONFIG_TYPE_CORIM:
            json_filenames = self.data.create_json_files()
            for json_filename in json_filenames:
                measurements = self.data.parse_json_file(json_filename)
                if not measurements:
                    continue
                self.data.display(json_filename)
                if is_not_blank(self.data.model):
                    self.create_cfm_file(self.data, self.output_filename.split(".")[0] + "_" + self.data.model + ".xml")
                else:
                    self.create_cfm_file(self.data, self.output_filename.split(".")[0] + "_" + smc_component_name + ".xml")

            for filename in os.listdir(smc_ws_dir):
                if filename.endswith(".json"):
                    filepath = os.path.join(smc_ws_dir, filename)
                    self.execute_command("rm -f " + filepath)
            self.execute_command("rm -rf " + smc_ws_dir)

    def display_model_list(self):
        """
        Display list of supported components/models for an input CoRIM file.
        Create a config file with list of supported components/models. By default,
        all supported models are part of include list. User can make changes to this
        file before passing it to this script for XML generation.
        """
        json_filenames = self.data.create_json_files()

        config_data = configparser.ConfigParser()
        autogen_filename = smc_component_name + '_' + smc_auto_gen_comp_filter_cfg_filename
        cfg_file = open(autogen_filename,'w')

        model_list = []
        print ("=================================================================================")
        print ("Input CoRIM file supports below components/models -")
        print ("=================================================================================")
        for json_filename in json_filenames:
            model_name = self.data.extract_model_name(json_filename)
            model_list.append(model_name)
            print ("*", model_name)
        print ("=================================================================================")

        model_str = ','.join(map(str, model_list))

        """
        Write model list to config file.
        Default all are part of include list.
        """
        config_data['Include List'] = {'-inc': model_str}
        config_data['Exclude List'] = {'-exc': ""}
        config_data.write(cfg_file)
        cfg_file.close()

        print ("=================================================================================")
        print ("Component list config file generated= ", autogen_filename)
        print ("=================================================================================")

        """
        Delete intermediate files and directory.
        """
        for filename in os.listdir(smc_ws_dir):
            if filename.endswith(".json"):
                filepath = os.path.join(smc_ws_dir, filename)
                self.execute_command("rm -f " + filepath)
        self.execute_command("rm -rf " + smc_ws_dir)

def cmd_validate_input_args(component_name, input_filename, output_filename, filetype):
    """
    Validates the input arguments.
   
    :param component_name: Component name
    :param input_filename: Input filename
    :param output_filename: Output filename
    :param filetype: File Type

    :return 0 on success and -1 on failure
    """
    
    if component_name == None:
        return -1
    if input_filename == None:
        return -1
    if output_filename == None:
        return -1
    if (filetype != CONFIG_TYPE_RIM and filetype != CONFIG_TYPE_CORIM):
        return -1
    return 0

def cmd_validate_optional_input_args(slot_num, rootca_digest, base_hash_alg, meas_hash_alg, signed_flag, workspace_dir, smc_output_dir, exclude_list, include_list):
    """
    Validates the optional input arguments.

    :param slot_num: Slot Number
    :param rootca_digest: RootCA Digest
    :param base_hash_alg: Base Hash Algorithm
    :param meas_hash_alg: Meas Hash Algorithm
    :param signed_flag: Flag to indicate input file is signed_flag or not
    :param workspace_dir: Folder to store intermediate files
    :param smc_output_dir: Output directory to store xml files
    :param exclude_list: List of components excluded from CFM generation
    :param include_list: List of components included for CFM generation

    :return 0 on success and -1 on failure
    """

    if slot_num == None:
        return -1
    if rootca_digest == None:
        return -1
    if base_hash_alg == None:
        return -1
    if meas_hash_alg == None:
        return -1
    if workspace_dir == None:
        return -1
    if smc_output_dir == None:
        return -1
    if (smc_filetype != CONFIG_TYPE_CORIM) and (smc_get_comp_list == True):
        warnings.warn("Input filetype format doesn't support multiple components.", stacklevel=2)
        return -1
    if (smc_filetype != CONFIG_TYPE_CORIM) and (include_list or exclude_list):
        warnings.warn("Input filetype format doesn't require include/exclude list inputs.", stacklevel=2)
        return -1
    if (smc_filetype == CONFIG_TYPE_CORIM) and (include_list or exclude_list) and (smc_get_comp_list == True):
        warnings.warn("-l/--comp_list and -inc/-exc both cannot be used together in the same command.", stacklevel=2)
        return -1
    if include_list and exclude_list:
        warnings.warn("Use either include_list or exclude_list option. Both cannot be used together.", stacklevel=2)
        return -1

    return 0

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description = 'SPDM Measurements to CFM')
    parser.add_argument ('component_name', help = 'Component Name')
    parser.add_argument ('input_filename', help = 'Input SPDM Measurement File')

    #optional args
    parser.add_argument('-d', '--debug', action="store_true", help = 'Enable debuggging')
    parser.add_argument('-l', '--get_comp_list', action="store_true", help = 'Get list of supported components')
    parser.add_argument ('-c', '--comp_filter_file', help = 'Config file containing Include/Exclude component lists')
    parser.add_argument ('-f', '--comp_def_file', help = 'Config file containing defaults for each CoRIM/RIM file')

    args = parser.parse_args()

    smc_component_name = args.component_name
    smc_input_filename = args.input_filename

    #oprtional args
    if args.debug:
        smc_debug = True
    if args.get_comp_list:
        smc_get_comp_list = args.get_comp_list
    if args.comp_filter_file:
        smc_comp_filter_cfg_filename = args.comp_filter_file
    if args.comp_def_file:
        smc_comp_def_cfg_filename = args.comp_def_file

    """
    Populate defaults and component specific parameters from component map config file.
    """
    config_data = configparser.ConfigParser()
    map_file = os.path.join (os.path.dirname (os.path.abspath (__file__)), smc_comp_def_cfg_filename)
    if (os.path.isfile(map_file)):
        config_data.read(map_file)
    else:
        warnings.warn("File " + smc_comp_def_cfg_filename + " is missing!", stacklevel=2)
        exit()

    smc_output_filename = config_data.get(COMPONENT_MAP_DEFAULTS_SECTION,COMPONENT_MAP_DEFAULT_OUTPUT_FILENAME)
    smc_ws_dir = config_data.get(COMPONENT_MAP_DEFAULTS_SECTION,COMPONENT_MAP_DEFAULT_WORKSPACE_DIR)
    smc_slot_num = config_data.get(COMPONENT_MAP_DEFAULTS_SECTION,COMPONENT_MAP_DEFAULT_SLOT_NUM)
    smc_filetype = config_data.get(smc_component_name,COMPONENT_MAP_FILE_TYPE)
    smc_rootca_digest = config_data.get(smc_component_name,COMPONENT_MAP_ROOTCA_DIGEST_VAL)
    smc_base_hash_alg = config_data.get(smc_component_name,COMPONENT_MAP_BASE_HASH_ALGO)
    smc_meas_hash_alg = config_data.get(smc_component_name,COMPONENT_MAP_MEASURE_HASH_ALGO)
    smc_signed_flag = config_data.get(smc_component_name,COMPONENT_MAP_SIGNED_FLAG)

    """
    Populate include and exclude list from input component list config file.
    """
    if (not smc_get_comp_list):
        filter_file = os.path.join (os.path.dirname (os.path.abspath (__file__)), smc_comp_filter_cfg_filename)
        if (os.path.isfile(filter_file)):
            config_data.read(filter_file)

            inc_list = config_data.get('Include List','-inc')
            if inc_list:
                smc_component_inc_list = inc_list.split(',')

            exc_list = config_data.get('Exclude List','-exc')
            if exc_list:
                smc_component_exc_list = exc_list.split(',')
        else:
            warnings.warn("File " + smc_comp_filter_cfg_filename + " is missing!\n"
                    "Check if the filename is correct.", stacklevel=2)
            exit()

        """
        Create an output directory to store .xml files like in Pipeline
        """
        smc_output_dir = smc_output_filename.split('/')[0]

    if (cmd_validate_input_args(smc_component_name, smc_input_filename, smc_output_filename, smc_filetype) != 0):
        exit()

    print("Input Args: component_name=", smc_component_name, "input_filename=", smc_input_filename, "output_filename=", smc_output_filename,
            "smc_filetype=", smc_filetype)

    if (cmd_validate_optional_input_args(smc_slot_num, smc_rootca_digest, smc_base_hash_alg,
            smc_meas_hash_alg, smc_signed_flag, smc_ws_dir, smc_output_dir, smc_component_exc_list, smc_component_inc_list) != 0):
        exit()

    print("Optional Input Args: smc_slot_num=", smc_slot_num, "smc_rootca_digest=", smc_rootca_digest,
            "smc_base_hash_alg=", smc_base_hash_alg, "smc_meas_hash_alg=", smc_meas_hash_alg, "smc_signed_flag=", smc_signed_flag, "smc_ws_dir=", smc_ws_dir, "smc_get_comp_list=", smc_get_comp_list, "smc_component_inc_list=", smc_component_inc_list, "smc_component_exc_list=", smc_component_exc_list)

    config = SPDM_Measurement_Config(smc_slot_num, smc_rootca_digest, smc_base_hash_alg,
            smc_meas_hash_alg)
    data = SPDM_Measurement_Data(smc_input_filename, smc_output_filename, smc_filetype, config)

    if (smc_get_comp_list) and (smc_filetype == CONFIG_TYPE_CORIM):
        data.display_model_list()
    else:
        data.convert_to_cfm()
