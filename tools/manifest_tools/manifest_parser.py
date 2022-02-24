"""
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the MIT license.
"""

from __future__ import print_function
from __future__ import unicode_literals
import re
import binascii
import traceback
import xml.etree.ElementTree as et
import manifest_types


XML_ATTESTATION_PROTOCOL_ATTRIB = "attestation_protocol"
XML_CONNECTION_ATTRIB = "connection"
XML_COUNT_ATTRIB = "count"
XML_EMPTY_ATTRIB = "empty"
XML_ENTRY_ID_ATTRIB = "entry_id"
XML_ID_ATTRIB = "id"
XML_INDEX_ATTRIB = "index"
XML_MEASUREMENT_ID_ATTRIB = "measurement_id"
XML_LEVEL_ATTRIB = "level"
XML_PLATFORM_ATTRIB = "platform"
XML_PMR_ID_ATTRIB = "pmr_id"
XML_PORT_ATTRIB = "port"
XML_SKU_ATTRIB = "sku"
XML_SLOT_NUM_ATTRIB = "slot_num"
XML_TYPE_ATTRIB = "type"
XML_VERSION_ATTRIB = "version"

XML_ACTIVE_TAG = "Active"
XML_ADDRESS_TAG = "Address"
XML_ALLOWABLE_CFM_TAG = "AllowableCFM"
XML_ALLOWABLE_DATA_TAG = "AllowableData"
XML_ALLOWABLE_PCD_TAG = "AllowablePCD"
XML_ALLOWABLE_PFM_TAG = "AllowablePFM"
XML_BITMASK_TAG = "Bitmask"
XML_BRIDGE_ADDRESS_TAG = "BridgeAddress"
XML_BRIDGE_EID_TAG = "BridgeEID"
XML_BUS_TAG = "Bus"
XML_CHANNEL_TAG = "Channel"
XML_CHECK_TAG = "Check"
XML_COMPONENT_TAG = "Component"
XML_CFM_COMPONENT_TAG = "CFMComponent"
XML_COMPONENTS_TAG = "Components"
XML_DATA_TAG = "Data"
XML_DEVICE_ID_TAG = "DeviceID"
XML_DEVICETYPE_TAG = "DeviceType"
XML_DIGEST_TAG = "Digest"
XML_EID_TAG = "EID"
XML_END_ADDR_TAG = "EndAddr"
XML_FAILURE_ACTION_TAG = "FailureAction"
XML_FW_TAG = "Firmware"
XML_FLASHMODE_TAG = "FlashMode"
XML_HASH_TAG = "Hash"
XML_HASH_TYPE_TAG = "HashType"
XML_I2CMODE_TAG = "I2CMode"
XML_ID_TAG = "ID"
XML_INITIAL_VALUE_TAG = "InitialValue"
XML_INTERFACE_TAG = "Interface"
XML_MASK_TAG = "Mask"
XML_MANIFEST_ID_TAG = "ManifestID"
XML_MEASUREMENT_TAG = "Measurement"
XML_MEASUREMENT_DATA_TAG = "MeasurementData"
XML_MUX_TAG = "Mux"
XML_MUXES_TAG = "Muxes"
XML_OPERATION_ON_FAILURE_TAG = "OperationOnFailure"
XML_PMR_TAG = "PMR"
XML_PMR_DIGEST_TAG = "PMRDigest"
XML_POLICY_TAG = "Policy"
XML_PORT_TAG = "Port"
XML_PORTS_TAG = "Ports"
XML_POWER_CONTROLLER_TAG = "PowerController"
XML_PB_KEY_TAG = "PublicKey"
XML_PULSEINTERVAL_TAG = "PulseInterval"
XML_PWRCTRL_TAG = "PwrCtrl"
XML_RW_TAG = "ReadWrite"
XML_REGION_TAG = "Region"
XML_REGISTER_TAG = "Register"
XML_RESETCTRL_TAG = "ResetCtrl"
XML_ROOT_CA_DIGEST_TAG = "RootCADigest"
XML_ROT_TAG = "RoT"
XML_ROT_EID_TAG = "RoTEID"
XML_RUNTIME_UPDATE_TAG = "RuntimeUpdate"
XML_RUNTIMEVERIFICATION_TAG = "RuntimeVerification"
XML_SIG_TAG = "Signature"
XML_IMG_TAG = "SignedImage"
XML_SPIFREQ_TAG = "SPIFreq"
XML_START_ADDR_TAG = "StartAddr"
XML_SUB_DEVICE_ID_TAG = "SubsystemDeviceID"
XML_SUB_VENDOR_ID_TAG = "SubsystemVendorID"
XML_UNUSED_BYTE_TAG = "UnusedByte"
XML_WATCHDOGMONITORING_TAG = "WatchdogMonitoring"
XML_VALIDATE_TAG = "ValidateOnBoot"
XML_VENDOR_ID_TAG = "VendorID"
XML_VERSION_TAG = "Version"
XML_VERSION_ADDR_TAG = "VersionAddr"

PCD_ROT_TYPE_PA_ROT = "PA-RoT"
PCD_ROT_TYPE_AC_ROT = "AC-RoT"
PCD_FLASH_MODE_SINGLE = "Single"
PCD_FLASH_MODE_DUAL = "Dual"
PCD_FLASH_MODE_SINGLE_FILTERED_BYPASS = "SingleFilteredBypass"
PCD_FLASH_MODE_DUAL_FILTERED_BYPASS = "DualFilteredBypass"
PCD_RESET_CTRL_NOTIFY = "Notify"
PCD_RESET_CTRL_RESET = "Reset"
PCD_RESET_CTRL_PULSE = "Pulse"
PCD_POLICY_ACTIVE = "Active"
PCD_POLICY_PASSIVE = "Passive"
PCD_INTERFACE_TYPE_I2C = "I2C"
PCD_INTERFACE_I2C_MODE_MM = "MultiMaster"
PCD_INTERFACE_I2C_MODE_MS = "MasterSlave"
PCD_COMPONENT_CONNECTION_DIRECT = "Direct"
PCD_COMPONENT_CONNECTION_MCTP_BRIDGE = "MCTPBridge"
PCD_ENABLED = "Enabled"
PCD_DISABLED = "Disabled"

CFM_CHECK_EQUAL = "Equal"
CFM_CHECK_NOT_EQUAL = "NotEqual"
CFM_CHECK_LESS_THAN = "LessThan"
CFM_CHECK_LESS_OR_EQUAL = "LessOrEqual"
CFM_CHECK_GREATER_THAN = "GreaterThan"
CFM_CHECK_GREATER_OR_EQUAL = "GreaterOrEqual"


def xml_extract_attrib (root, attrib_name, string, xml_file, required=True):
    """
    Fetch attribute from an XML tag.

    :param root: XML tag to utilize
    :param attrib_name: Attribute to fetch
    :param string: A boolean indicating whether attribute value is expected to be a string
    :param xml_file: Filename of XML
    :param key: A boolean indicating whether attribute is required for a valid manifest XML

    :return Attribute value
    """

    attrib = root.attrib.get (attrib_name)
    if not attrib:
        if required:
            raise KeyError ("Missing {0} attribute in manifest {1}".format (attrib_name, xml_file))
        return None

    if string:
        attrib.encode ("utf8")

    return attrib.strip ()

def xml_find_single_tag (root, tag_name, xml_file, required=True):
    """
    Fetch an XML tag from XML.

    :param root: XML to utilize
    :param tag_name: Name of tag to fetch
    :param key: A boolean indicating whether tag is required for a valid manifest XML
    :param xml_file: Filename of XML

    :return Tag if found
    """

    tag = root.findall (tag_name)
    if not tag:
        if required:
            raise KeyError ("Missing {0} tag in manifest {1}".format (tag_name, xml_file))
        return None
    elif len (tag) > 1:
        raise ValueError ("Too many {0} tags in manifest {1}".format (tag_name, xml_file))

    return tag[0]

def xml_extract_single_value (root, requests, xml_file):
    """
    Fetch element values from XML tag.

    :param root: XML tag to utilize
    :param requests: A list of XML elements to get values of
    :param xml_file: Filename of XML

    :return Dictionary of elements and their values
    """

    result = {}

    for name, tag_name in requests.items ():
        tag = root.findall (tag_name)
        if not tag:
            raise KeyError ("Missing {0} tag in manifest {1}".format (tag_name, xml_file))
        elif len (tag) > 1:
            raise ValueError ("Too many {0} tags in manifest {1}".format (tag_name, xml_file))

        result.update ({name:tag[0].text.strip ()})

    return result

def process_pfm (root, xml_file):
    """
    Process PFM XML and generate list of element and attribute values.

    :param root: XML to utilize
    :param xml_file: Name of XML file to process

    :return List of PFM values, manifest version, a boolean False since PFM XMLs are never empty
    """

    def process_region (root, version_id, xml_file):
        region = {}

        addr = xml_find_single_tag (root, XML_START_ADDR_TAG, xml_file)
        region["start"] = addr.text.strip ()

        addr = xml_find_single_tag (root, XML_END_ADDR_TAG, xml_file)
        region["end"] = addr.text.strip ()

        return region

    xml = {}
    pfm_version = manifest_types.VERSION_1

    result = xml_extract_attrib (root, XML_VERSION_ATTRIB, True, xml_file)
    xml.update ({"version_id":result})

    result = xml_extract_attrib (root, XML_PLATFORM_ATTRIB, True, xml_file)
    xml.update ({"platform_id":result})

    firmware_type = xml_extract_attrib (root, XML_TYPE_ATTRIB, True, xml_file, False)
    if firmware_type is not None:
        pfm_version = manifest_types.VERSION_2
        xml["fw_type"] = firmware_type

        runtime_update = xml_find_single_tag (root, XML_RUNTIME_UPDATE_TAG, xml_file)

        xml["runtime_update"] = runtime_update.text.strip ().lower ()

    version_addr = xml_find_single_tag (root, XML_VERSION_ADDR_TAG, xml_file)

    xml["version_addr"] = version_addr.text.strip ()

    unused_byte = xml_find_single_tag (root, XML_UNUSED_BYTE_TAG, xml_file, False)
    if unused_byte is not None:
        xml["unused_byte"] = unused_byte.text.strip ()
    else:
        xml["unused_byte"] = "0xff"

    xml["rw_regions"] = []

    for rw in root.findall (XML_RW_TAG):
        for region in rw.findall (XML_REGION_TAG):
            processed_region = process_region (region, xml["version_id"], xml_file)
            if processed_region is None:
                raise ValueError ("Failed to process RW region")
            else:
                if pfm_version == manifest_types.VERSION_2:
                    fail_operation = xml_find_single_tag (region, XML_OPERATION_ON_FAILURE_TAG,
                        xml_file, False)
                    if fail_operation is None or fail_operation.text.strip () == "Nothing":
                        processed_region["operation_fail"] = "0x0"
                    elif fail_operation.text.strip () == "Erase":
                        processed_region["operation_fail"] = "0x2"
                    elif fail_operation.text.strip () == "Restore":
                        processed_region["operation_fail"] = "0x1"
                    else:
                        raise ValueError (
                            "Unknown operation on failure setting '{0}' for RW region (start: 0x{1}, end: 0x{2})".format (
                                fail_operation.text.strip (), processed_region["start"],
                                processed_region["end"]))

            xml["rw_regions"].append (processed_region)

    xml["signed_imgs"] = []

    for img in root.findall (XML_IMG_TAG):
        image = {}
        image["regions"] = []

        if pfm_version == manifest_types.VERSION_2:
            img_hash = xml_find_single_tag (img, XML_HASH_TAG, xml_file)
            image["hash"] = binascii.a2b_hex (re.sub ("\s", "", img_hash.text.strip ()))

            hash_type = xml_find_single_tag (img, XML_HASH_TYPE_TAG, xml_file, False)
            if hash_type is None or hash_type.text.strip () == "SHA256":
                image["hash_type"] = "0x0"
            elif hash_type.text.strip () == "SHA512":
                image["hash_type"] = "0x2"
            elif hash_type.text.strip () == "SHA384":
                image["hash_type"] = "0x1"
            else:
                raise ValueError ("Unknown hash type '{0}' in signed image".format (
                    hash_type.text.strip ()))
        else:
            pbkey = xml_find_single_tag (img, XML_PB_KEY_TAG, xml_file)
            image["pbkey"] = pbkey.text.strip ()

            sig = xml_find_single_tag (img, XML_SIG_TAG, xml_file)
            image["signature"] = binascii.a2b_hex (re.sub ("\s", "", sig.text.strip ()))

        for region in img.findall (XML_REGION_TAG):
            processed_region = process_region (region, xml["version_id"], xml_file)
            if processed_region is None:
                raise ValueError ("Failed to process signed image")

            image["regions"].append (processed_region)

        if not image["regions"]:
            raise ValueError ("No regions found for SignedImage, firmware: {0}".format (
                xml["version_id"]))

        prop = xml_find_single_tag (img, XML_VALIDATE_TAG, xml_file)
        image["validate"] = prop.text.strip ()

        xml["signed_imgs"].append (image)

    if not xml["signed_imgs"]:
        raise ValueError ("No signed images found for firmware: {0}".format (xml["version_id"]))

    return xml, pfm_version, False

def process_cfm_check (root, manifest_name, component_type, xml_file):
    result = xml_extract_single_value (root, {"check": XML_CHECK_TAG}, xml_file)
    if result["check"] is None or result["check"] == CFM_CHECK_EQUAL:
        return 0
    elif result["check"] == CFM_CHECK_NOT_EQUAL:
        return 1
    elif result["check"] == CFM_CHECK_LESS_THAN:
        return 2
    elif result["check"] == CFM_CHECK_LESS_OR_EQUAL:
        return 3
    elif result["check"] == CFM_CHECK_GREATER_THAN:
        return 4
    elif result["check"] == CFM_CHECK_GREATER_OR_EQUAL:
        return 5
    else:
        raise ValueError (
            "Unknown check type '{0}' in allowable {1} for component {2} in manifest {3}".format (
                result["check"], manifest_name, component_type, xml_file))

def process_cfm_allowable_manifest (root, manifest_name, component_type, xml_file):
    output = {}
    output["manifest_id"] = []

    for manifest_id in root.findall (XML_MANIFEST_ID_TAG):
        ids = []

        for id in manifest_id.findall (XML_ID_TAG):
            ids.append (int (id.text.strip (), 16))

        check = process_cfm_check (manifest_id, manifest_name, component_type, xml_file)

        output["manifest_id"].append ({"check":check, "ids": ids})

    return output

def process_cfm (root, xml_file, selection_list):
    """
    Process CFM XML and generate list of element and attribute values.

    :param root: XML to utilize
    :param xml_file: Filename of XML
    :param selection_list: List of component types to include

    :return List of CFM values, manifest version, boolean for whether manifest is for an empty CFM
    """

    xml = {}

    component_type = xml_extract_attrib (root, XML_TYPE_ATTRIB, True, xml_file)
    component_type = component_type.strip ('\"')

    if component_type not in selection_list:
        return None, manifest_types.VERSION_2, False

    xml[component_type] = {}
    component = xml[component_type]

    result = xml_extract_attrib (root, XML_ATTESTATION_PROTOCOL_ATTRIB, True, xml_file)
    if result.lower () == "cerberus":
        component["attestation_protocol"] = 0
    elif result.lower () == "spdm":
        component["attestation_protocol"] = 1
    else:
        raise ValueError ("Component {0} has unknown attestation protocol '{1}' in {2}".format (
            component_type, result, xml_file))

    component["slot_num"] = int (xml_extract_attrib (root, XML_SLOT_NUM_ATTRIB, False, xml_file))

    for root_ca_digests in root.findall (XML_ROOT_CA_DIGEST_TAG):
        if "root_ca_digests" in component:
            raise ValueError ("Component {0} has multiple root CA digest entries in {1}".format (
                component_type, xml_file))

        component["root_ca_digests"] = {}

        result = xml_extract_single_value (root_ca_digests, {"hash_type": XML_HASH_TYPE_TAG},
            xml_file)

        if result["hash_type"] is None or result["hash_type"] == "SHA256":
            component["root_ca_digests"]["hash_type"] = 0
        elif result["hash_type"] == "SHA384":
            component["root_ca_digests"]["hash_type"] = 1
        elif result["hash_type"] == "SHA512":
            component["root_ca_digests"]["hash_type"] = 2
        else:
            raise ValueError ("Unknown hash type '{0}' in root CA digests".format (
                result["hash_type"]))

        component["root_ca_digests"]["allowable_digests"] = []

        for allowable_digest in root_ca_digests.findall (XML_DIGEST_TAG):
            component["root_ca_digests"]["allowable_digests"].append (
                binascii.a2b_hex (re.sub ("\s", "", allowable_digest.text.strip ())))

    for pmr in root.findall (XML_PMR_TAG):
        if "pmr" not in component:
            component["pmr"] = {}

        pmr_id = int (xml_extract_attrib (pmr, XML_PMR_ID_ATTRIB, False, xml_file))

        if pmr_id in component["pmr"]:
            raise ValueError (
                "Too many PMR elements for PMR ID {0} for component {1} in manifest {2}".format (
                    pmr_id, component_type, xml_file))

        component["pmr"][pmr_id] = xml_extract_single_value (pmr,
            {"hash_type": XML_HASH_TYPE_TAG, "initial_value": XML_INITIAL_VALUE_TAG}, xml_file)

        if component["pmr"][pmr_id]["hash_type"] is None or \
        component["pmr"][pmr_id]["hash_type"] == "SHA256":
            component["pmr"][pmr_id]["hash_type"] = 0
        elif component["pmr"][pmr_id]["hash_type"] == "SHA384":
            component["pmr"][pmr_id]["hash_type"] = 1
        elif component["pmr"][pmr_id]["hash_type"] == "SHA512":
            component["pmr"][pmr_id]["hash_type"] = 2
        else:
            raise ValueError (
                "Unknown hash type '{0}' in PMR ID {1} for component {2} in manifest {3}".format (
                    component["pmr"][pmr_id]["hash_type"], pmr_id), pmr_id, component_type,
                    xml_file)

        component["pmr"][pmr_id]["initial_value"] = binascii.a2b_hex (
            re.sub ("\s", "", component["pmr"][pmr_id]["initial_value"]))

    for pmr_digest in root.findall (XML_PMR_DIGEST_TAG):
        if "pmr_digests" not in component:
            component["pmr_digests"] = {}

        pmr_id = int (xml_extract_attrib (pmr_digest, XML_PMR_ID_ATTRIB, False, xml_file))

        if pmr_id in component["pmr_digests"]:
            raise ValueError (
                "Too many rules for PMR ID {0} digests for component {1} in manifest {2}".format (
                    pmr_id, component_type, xml_file))

        component["pmr_digests"][pmr_id] = {}

        result = xml_extract_single_value (pmr_digest, {"hash_type": XML_HASH_TYPE_TAG}, xml_file)

        if result["hash_type"] is None or result["hash_type"] == "SHA256":
            component["pmr_digests"][pmr_id]["hash_type"] = 0
        elif result["hash_type"] == "SHA384":
            component["pmr_digests"][pmr_id]["hash_type"] = 1
        elif result["hash_type"] == "SHA512":
            component["pmr_digests"][pmr_id]["hash_type"] = 2
        else:
            raise ValueError ("Unknown hash type '{0}' in PMR digest".format (result["hash_type"]))

        component["pmr_digests"][pmr_id]["allowable_digests"] = []

        for allowable_digest in pmr_digest.findall (XML_DIGEST_TAG):
            component["pmr_digests"][pmr_id]["allowable_digests"].append (
                binascii.a2b_hex (re.sub ("\s", "", allowable_digest.text.strip ())))

    for measurement in root.findall (XML_MEASUREMENT_TAG):
        if "measurements" not in component:
            component["measurements"] = {}

        pmr_id = int (xml_extract_attrib (measurement, XML_PMR_ID_ATTRIB, False, xml_file))
        measurement_id = int (xml_extract_attrib (measurement, XML_MEASUREMENT_ID_ATTRIB, False,
            xml_file))

        if pmr_id in component["measurements"]:
            if measurement_id in component["measurements"][pmr_id]:
                raise ValueError (
                    "Too many rules for PMR ID {0} measurement ID {1} for component {2} in manifest {3}".format (
                        pmr_id, measurement_id, component_type, xml_file))
        else:
            component["measurements"][pmr_id] = {}

        component["measurements"][pmr_id][measurement_id] = {}

        result = xml_extract_single_value (measurement, {"hash_type": XML_HASH_TYPE_TAG}, xml_file)

        if result["hash_type"] is None or result["hash_type"] == "SHA256":
            component["measurements"][pmr_id][measurement_id]["hash_type"] = 0
        elif result["hash_type"] == "SHA384":
            component["measurements"][pmr_id][measurement_id]["hash_type"] = 1
        elif result["hash_type"] == "SHA512":
            component["measurements"][pmr_id][measurement_id]["hash_type"] = 2
        else:
            raise ValueError ("Unknown hash type '{0}' in signed image".format (
                result["hash_type"]))

        component["measurements"][pmr_id][measurement_id]["allowable_digests"] = []

        for allowable_digest in measurement.findall (XML_DIGEST_TAG):
            component["measurements"][pmr_id][measurement_id]["allowable_digests"].append (
                binascii.a2b_hex (re.sub ("\s", "", allowable_digest.text.strip ())))

    for measurement_data in root.findall (XML_MEASUREMENT_DATA_TAG):
        if "measurement_data" not in component:
            component["measurement_data"] = {}

        pmr_id = int (xml_extract_attrib (measurement_data, XML_PMR_ID_ATTRIB, False, xml_file))
        measurement_id = int (xml_extract_attrib (measurement_data, XML_MEASUREMENT_ID_ATTRIB,
            False, xml_file))

        if pmr_id in component["measurement_data"]:
            if measurement_id in component["measurement_data"][pmr_id]:
                raise ValueError (
                    "Too many rules for PMR ID {0} measurement data ID {1} for component {2} in manifest {3}".format (
                        pmr_id, measurement_id, component_type, xml_file))
        else:
            component["measurement_data"][pmr_id] = {}

        component["measurement_data"][pmr_id][measurement_id] = {}
        component["measurement_data"][pmr_id][measurement_id]["allowable_data"] = []

        for allowable_data in measurement_data.findall (XML_ALLOWABLE_DATA_TAG):
            data_dict = {}
            data_dict["data"] = []

            bitmask_tag = xml_find_single_tag (allowable_data, XML_BITMASK_TAG, xml_file, False)

            if bitmask_tag is not None:
                bitmask_tag_text = bitmask_tag.text.strip ()
                data_dict["bitmask"] = binascii.a2b_hex (re.sub ("\s", "", bitmask_tag_text))

            check = process_cfm_check (allowable_data, "data", component_type, xml_file)
            data_dict["check"] = check

            for data in allowable_data.findall (XML_DATA_TAG):
                data_text = data.text.strip ()
                if data_text[0] == '"' and data_text[-1] == '"':
                    data_text = binascii.hexlify (data_text.strip ('\"').encode ())
                else:
                    data_text = re.sub ("\s", "", data_text)

                data_text = binascii.a2b_hex (data_text)

                if "data_len" in component["measurement_data"][pmr_id][measurement_id]:
                    data_len = component["measurement_data"][pmr_id][measurement_id]["data_len"]
                    if len (data_text) != data_len:
                        raise ValueError (
                            "Data {0} has different length than other data for component {1} in manifest {2}: {3} vs {4}".format (
                            data_text, component_type, xml_file, len (data_text), data_len))
                else:
                    component["measurement_data"][pmr_id][measurement_id]["data_len"] = \
                        len (data_text)

                if "bitmask" in data_dict and len (data_text) != len (data_dict["bitmask"]):
                    raise ValueError (
                        "Data {0} should be same length as bitmask {1} for component {2} in manifest {3}".format (
                            data_text, data_dict["bitmask"], component_type, xml_file))

                data_dict["data"].append(data_text)

            component["measurement_data"][pmr_id][measurement_id]["allowable_data"].append (
                data_dict)

    for allowable_pfm in root.findall (XML_ALLOWABLE_PFM_TAG):
        if "allowable_pfm" not in component:
            component["allowable_pfm"] = {}

        port_id = int (xml_extract_attrib (allowable_pfm, XML_PORT_ATTRIB, False, xml_file))
        platform = xml_extract_attrib (allowable_pfm, XML_PLATFORM_ATTRIB, True, xml_file)

        if port_id in component["allowable_pfm"]:
            raise ValueError ("Too many rules for port {0} PFMs for component {1} in manifest {2}".format (
                port_id, component_type, xml_file))

        component["allowable_pfm"][port_id] = process_cfm_allowable_manifest (allowable_pfm,
            "PFM", component_type, xml_file)
        component["allowable_pfm"][port_id]["platform"] = platform

    for allowable_cfm in root.findall (XML_ALLOWABLE_CFM_TAG):
        if "allowable_cfm" not in component:
            component["allowable_cfm"] = {}

        index = int (xml_extract_attrib (allowable_cfm, XML_INDEX_ATTRIB, False, xml_file))
        platform = xml_extract_attrib (allowable_cfm, XML_PLATFORM_ATTRIB, True, xml_file)

        if index in component["allowable_cfm"]:
            raise ValueError ("Too many rules for index {0} CFMs for component {1} in manifest {2}".format (
                index, component_type, xml_file))

        component["allowable_cfm"][index] = process_cfm_allowable_manifest (allowable_cfm,
            "CFM", component_type, xml_file)
        component["allowable_cfm"][index]["platform"] = platform

    allowable_pcd = xml_find_single_tag (root, XML_ALLOWABLE_PCD_TAG, xml_file, False)
    if allowable_pcd is not None:
        platform = xml_extract_attrib (allowable_pcd, XML_PLATFORM_ATTRIB, True, xml_file)
        component["allowable_pcd"] = process_cfm_allowable_manifest (allowable_pcd, "PCD",
            component_type, xml_file)
        component["allowable_pcd"]["platform"] = platform

    return xml, manifest_types.VERSION_2, False

def process_pcd (root, xml_file):
    """
    Process PCD XML and generate list of element and attribute values.

    :param root: XML to utilize
    :param xml_file: Filename of XML

    :return List of PCD values, manifest version, boolean for whether manifest is for an empty PCD
    """

    xml = {}

    result = xml_extract_attrib (root, XML_SKU_ATTRIB, True, xml_file)
    xml.update ({"platform_id":result})

    result = xml_extract_attrib (root, XML_VERSION_ATTRIB, False, xml_file)
    xml.update ({"version":int (result, 16)})

    result = xml_extract_attrib (root, XML_EMPTY_ATTRIB, True, xml_file, False)
    if result and result.lower () == "true":
        return xml, manifest_types.VERSION_2, True

    rot = xml_find_single_tag (root, XML_ROT_TAG, xml_file)

    xml["rot"] = {}

    result = xml_extract_attrib (rot, XML_TYPE_ATTRIB, True, xml_file)
    if result == PCD_ROT_TYPE_PA_ROT:
        result = 0
    elif result == PCD_ROT_TYPE_AC_ROT:
        result = 1
    else:
        raise ValueError ("Unknown RoT type: {0}".format (result))

    xml["rot"].update ({"type":result})

    ports = xml_find_single_tag (rot, XML_PORTS_TAG, xml_file, False)
    if ports is not None:
        xml["rot"]["ports"] = {}

        for port in ports.findall (XML_PORT_TAG):
            port_id = xml_extract_attrib (port, XML_ID_ATTRIB, False, xml_file)
            xml["rot"]["ports"][port_id] = {}

            result = xml_extract_single_value (port, {"spi_freq": XML_SPIFREQ_TAG,
                "flash_mode": XML_FLASHMODE_TAG, "reset_ctrl": XML_RESETCTRL_TAG,
                "policy": XML_POLICY_TAG, "pulse_interval": XML_PULSEINTERVAL_TAG,
                "runtime_verification": XML_RUNTIMEVERIFICATION_TAG,
                "watchdog_monitoring": XML_WATCHDOGMONITORING_TAG}, xml_file)

            if result["flash_mode"] == PCD_FLASH_MODE_DUAL:
                result["flash_mode"] = 0
            elif result["flash_mode"] == PCD_FLASH_MODE_SINGLE:
                result["flash_mode"] = 1
            elif result["flash_mode"] == PCD_FLASH_MODE_DUAL_FILTERED_BYPASS:
                result["flash_mode"] = 2
            elif result["flash_mode"] == PCD_FLASH_MODE_SINGLE_FILTERED_BYPASS:
                result["flash_mode"] = 3
            else:
                raise ValueError ("Unknown port {0} flash mode: {1}".format (port_id,
                    result["flash_mode"]))

            if result["reset_ctrl"] == PCD_RESET_CTRL_NOTIFY:
                result["reset_ctrl"] = 0
            elif result["reset_ctrl"] == PCD_RESET_CTRL_RESET:
                result["reset_ctrl"] = 1
            elif result["reset_ctrl"] == PCD_RESET_CTRL_PULSE:
                result["reset_ctrl"] = 2
            else:
                raise ValueError ("Unknown port {0} reset control: {1}".format (port_id,
                    result["reset_ctrl"]))

            if result["policy"] == PCD_POLICY_PASSIVE:
                result["policy"] = 0
            elif result["policy"] == PCD_POLICY_ACTIVE:
                result["policy"] = 1
            else:
                raise ValueError ("Unknown port {0} policy: {1}".format (port_id, result["policy"]))

            if result["runtime_verification"] == PCD_DISABLED:
                result["runtime_verification"] = 0
            elif result["runtime_verification"] == PCD_ENABLED:
                result["runtime_verification"] = 1
            else:
                raise ValueError ("Unknown port {0} runtime verification setting: {1}".format (
                    port_id, result["runtime_verification"]))

            if result["watchdog_monitoring"] == PCD_DISABLED:
                result["watchdog_monitoring"] = 0
            elif result["watchdog_monitoring"] == PCD_ENABLED:
                result["watchdog_monitoring"] = 1
            else:
                raise ValueError ("Unknown port {0} watchdog monitoring setting: {1}".format (
                    port_id, result["watchdog_monitoring"]))

            xml["rot"]["ports"].update ({port_id:result})

    interface = xml_find_single_tag (rot, XML_INTERFACE_TAG, xml_file)

    xml["rot"]["interface"] = {}

    interface_type = xml_extract_attrib (interface, XML_TYPE_ATTRIB, True, xml_file)
    if interface_type == PCD_INTERFACE_TYPE_I2C:
        interface_type = 0
    else:
        raise ValueError ("Unknown RoT interface type: {0}".format (interface_type))

    xml["rot"]["interface"].update ({"type":interface_type})

    result = xml_extract_single_value (interface, {"address": XML_ADDRESS_TAG,
        "rot_eid": XML_ROT_EID_TAG, "bridge_eid": XML_BRIDGE_EID_TAG,
        "bridge_address": XML_BRIDGE_ADDRESS_TAG}, xml_file)

    result["address"] = int (result["address"], 16)
    result["rot_eid"] = int (result["rot_eid"], 16)
    result["bridge_eid"] = int (result["bridge_eid"], 16)
    result["bridge_address"] = int (result["bridge_address"], 16)

    xml["rot"]["interface"].update (result)

    power_controller = xml_find_single_tag (root, XML_POWER_CONTROLLER_TAG, xml_file, False)
    if power_controller is not None:
        xml["power_controller"] = {}

        interface = xml_find_single_tag (power_controller, XML_INTERFACE_TAG, xml_file)

        xml["power_controller"]["interface"] = {}

        interface_type = xml_extract_attrib (interface, XML_TYPE_ATTRIB, True, xml_file)
        if interface_type == PCD_INTERFACE_TYPE_I2C:
            interface_type = 0
        else:
            print ("Unknown PowerController interface type: {0}".format (interface_type))

        xml["power_controller"]["interface"].update ({"type":interface_type})

        result = xml_extract_single_value (interface, {"bus": XML_BUS_TAG,
            "eid": XML_EID_TAG, "address": XML_ADDRESS_TAG, "i2c_mode": XML_I2CMODE_TAG}, xml_file)

        result["eid"] = int (result["eid"], 16)
        result["address"] = int (result["address"], 16)

        if result["i2c_mode"] is None:
            raise ValueError ("PowerController missing I2C mode")
        if result["i2c_mode"] == PCD_INTERFACE_I2C_MODE_MM:
            result["i2c_mode"] = 0
        elif result["i2c_mode"] == PCD_INTERFACE_I2C_MODE_MS:
            result["i2c_mode"] = 1
        else:
            raise ValueError ("Unknown PowerController interface I2C mode: {0}".format (
                result["i2c_mode"]))

        xml["power_controller"]["interface"].update (result)

        muxes = xml_find_single_tag (interface, XML_MUXES_TAG, xml_file, False)
        if muxes is not None:
            xml["power_controller"]["interface"]["muxes"] = {}

            for mux in muxes.findall (XML_MUX_TAG):
                level = xml_extract_attrib (mux, XML_LEVEL_ATTRIB, False, xml_file)

                result = xml_extract_single_value (mux, {"address": XML_ADDRESS_TAG,
                    "channel": XML_CHANNEL_TAG}, xml_file)

                result["address"] = int (result["address"], 16)

                xml["power_controller"]["interface"]["muxes"].update ({level:result})

    components = xml_find_single_tag (root, XML_COMPONENTS_TAG, xml_file, False)
    if components is not None:
        xml = []

        for component in components.findall (XML_COMPONENT_TAG):
            curr_component = {}

            result = xml_extract_attrib (component, XML_TYPE_ATTRIB, True, xml_file)
            curr_component.update ({"type":result})

            cnxn_type = xml_extract_attrib (component, XML_CONNECTION_ATTRIB, True, xml_file)
            if cnxn_type == PCD_COMPONENT_CONNECTION_DIRECT:
                curr_component.update ({"connection":PCD_COMPONENT_CONNECTION_DIRECT})

                interface = xml_find_single_tag (component, XML_INTERFACE_TAG, xml_file)

                curr_component["interface"] = {}

                interface_type = xml_extract_attrib (interface, XML_TYPE_ATTRIB, True, xml_file)
                if interface_type == PCD_INTERFACE_TYPE_I2C:
                    interface_type = 0
                else:
                    raise ValueError ("Unknown component {0} interface type: {1}".format (
                        curr_component["type"], interface_type))

                curr_component["interface"].update ({"type":interface_type})

                result = xml_extract_single_value (interface, {"bus": XML_BUS_TAG,
                    "eid": XML_EID_TAG, "address": XML_ADDRESS_TAG, "i2c_mode": XML_I2CMODE_TAG},
                    xml_file)

                result["eid"] = int (result["eid"], 16)
                result["address"] = int (result["address"], 16)

                if result["i2c_mode"] is None:
                    raise ValueError ("Component {0} missing I2C mode".format (
                        curr_component["type"]))
                if result["i2c_mode"] == PCD_INTERFACE_I2C_MODE_MM:
                    result["i2c_mode"] = 0
                elif result["i2c_mode"] == PCD_INTERFACE_I2C_MODE_MS:
                    result["i2c_mode"] = 1
                else:
                    print ("Unknown component {0} interface I2C mode: {1}".format (
                        curr_component["type"], result["i2c_mode"]))

                curr_component["interface"].update (result)

                muxes = xml_find_single_tag (interface, XML_MUXES_TAG, xml_file, False)
                if muxes is not None:
                    curr_component["interface"]["muxes"] = {}

                    for mux in muxes.findall (XML_MUX_TAG):
                        level = xml_extract_attrib (mux, XML_LEVEL_ATTRIB, False, xml_file)
                        result = xml_extract_single_value (mux, {"address": XML_ADDRESS_TAG,
                            "channel": XML_CHANNEL_TAG}, xml_file)

                        result["address"] = int (result["address"], 16)

                        curr_component["interface"]["muxes"].update ({level:result})

            elif cnxn_type == PCD_COMPONENT_CONNECTION_MCTP_BRIDGE:
                curr_component.update ({"connection":PCD_COMPONENT_CONNECTION_MCTP_BRIDGE})

                count = xml_extract_attrib (component, XML_COUNT_ATTRIB, False, xml_file)
                curr_component.update ({"count": int (count)})

                result = xml_extract_single_value (component, {"eid": XML_EID_TAG,
                    "deviceid": XML_DEVICE_ID_TAG, "vendorid": XML_VENDOR_ID_TAG,
                    "subdeviceid": XML_SUB_DEVICE_ID_TAG, "subvendorid": XML_SUB_VENDOR_ID_TAG},
                    xml_file)

                result["eid"] = int (result["eid"], 16)
                result["deviceid"] = int (result["deviceid"], 16)
                result["vendorid"] = int (result["vendorid"], 16)
                result["subdeviceid"] = int (result["subdeviceid"], 16)
                result["subvendorid"] = int (result["subvendorid"], 16)

                curr_component.update (result)
            else:
                raise ValueError ("Unknown component {0} connection type: {1}".format (
                    curr_component["type"], cnxn_type))

            result = xml_extract_single_value (component, {"policy": XML_POLICY_TAG}, xml_file)
            if result["policy"] == PCD_POLICY_PASSIVE:
                result["policy"] = 0
            elif result["policy"] == PCD_POLICY_ACTIVE:
                result["policy"] = 1
            else:
                raise ValueError ("Unknown component {0} policy: {1}".format (
                    curr_component["type"], result["policy"]))

            curr_component.update (result)

            powerctrl = xml_find_single_tag (component, XML_PWRCTRL_TAG, xml_file)

            curr_component["powerctrl"] = {}

            result = xml_extract_single_value (powerctrl, {"register": XML_REGISTER_TAG,
                "mask": XML_MASK_TAG}, xml_file)

            result["register"] = int (result["register"], 16)
            result["mask"] = int (result["mask"], 16)

            curr_component["powerctrl"].update (result)

            xml.append (curr_component)

    return xml, manifest_types.VERSION_2, False

def load_and_process_xml (xml_file, xml_type, selection_list=None):
    """
    Process XML and generate list of element and attribute values.

    :param xml_file: XML to utilize
    :param xml_type: Type of manifest
    :param selection_list: Optional list of units to select and include in manifest

    :return List of manifest values, manifest version, boolean for whether XML is for an empty
        manifest
    """

    root = et.parse (xml_file).getroot ()

    if xml_type is manifest_types.PFM:
        return process_pfm (root, xml_file)
    elif xml_type is manifest_types.CFM:
        return process_cfm (root, xml_file, selection_list["selection"])
    elif xml_type is manifest_types.PCD:
        return process_pcd (root, xml_file)
    else:
        raise ValueError ("Unknown XML type: {0}".format (xml_type))

def load_and_process_selection_xml (xml_file):
    """
    Process XML and generate dictionary of platform ID and selection list.

    :param xml_file: XML to utilize

    :return selection dictionary
    """

    result_dict = {}

    root = et.parse (xml_file).getroot ()

    result = xml_extract_attrib (root, XML_SKU_ATTRIB, True, xml_file)
    result_dict.update ({"platform_id":result})

    result_dict["selection"] = []

    for component in root.findall (XML_COMPONENT_TAG):
        component_text = component.text.strip ().strip ("\"")
        result_dict["selection"].append (component_text)

    return result_dict

