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


XML_ID_ATTRIB = "id"
XML_VERSION_ATTRIB = "version"
XML_PLATFORM_ATTRIB = "platform"
XML_SKU_ATTRIB = "sku"
XML_LEVEL_ATTRIB = "level"
XML_TYPE_ATTRIB = "type"
XML_CONNECTION_ATTRIB = "connection"
XML_COUNT_ATTRIB = "count"
XML_EMPTY_ATTRIB = "empty"

XML_FW_TAG = "Firmware"
XML_DIGEST_TAG = "Digest"
XML_FAILURE_ACTION_TAG = "FailureAction"
XML_RW_TAG = "ReadWrite"
XML_REGION_TAG = "Region"
XML_IMG_TAG = "SignedImage"
XML_START_ADDR_TAG = "StartAddr"
XML_END_ADDR_TAG = "EndAddr"
XML_PB_KEY_TAG = "PublicKey"
XML_SIG_TAG = "Signature"
XML_VALIDATE_TAG = "ValidateOnBoot"
XML_VERSION_ADDR_TAG = "VersionAddr"
XML_UNUSED_BYTE_TAG = "UnusedByte"
XML_VERSION_TAG = "Version"
XML_ROT_TAG = "RoT"
XML_PORTS_TAG = "Ports"
XML_PORT_TAG = "Port"
XML_INTERFACE_TAG = "Interface"
XML_ADDRESS_TAG = "Address"
XML_ROT_EID_TAG = "RoTEID"
XML_BRIDGE_EID_TAG = "BridgeEID"
XML_BRIDGE_ADDRESS_TAG = "BridgeAddress"
XML_EID_TAG = "EID"
XML_POWER_CONTROLLER_TAG = "PowerController"
XML_CHANNEL_TAG = "Channel"
XML_COMPONENTS_TAG = "Components"
XML_COMPONENT_TAG = "Component"
XML_DEVICETYPE_TAG = "DeviceType"
XML_BUS_TAG = "Bus"
XML_I2CMODE_TAG = "I2CMode"
XML_PWRCTRL_TAG = "PwrCtrl"
XML_REGISTER_TAG = "Register"
XML_MASK_TAG = "Mask"
XML_MUXES_TAG = "Muxes"
XML_MUX_TAG = "Mux"
XML_POLICY_TAG = "Policy"
XML_ACTIVE_TAG = "Active"
XML_SPIFREQ_TAG = "SPIFreq"
XML_RESETCTRL_TAG = "ResetCtrl"
XML_FLASHMODE_TAG = "FlashMode"
XML_PULSEINTERVAL_TAG = "PulseInterval"
XML_RUNTIMEVERIFICATION_TAG = "RuntimeVerification"
XML_WATCHDOGMONITORING_TAG = "WatchdogMonitoring"
XML_RUNTIME_UPDATE_TAG = "RuntimeUpdate"
XML_OPERATION_ON_FAILURE_TAG = "OperationOnFailure"
XML_IMAGE_HASH_TAG = "Hash"
XML_IMAGE_HASH_TYPE_TAG = "HashType"
XML_DEVICE_ID_TAG = "DeviceID"
XML_VENDOR_ID_TAG = "VendorID"
XML_SUB_DEVICE_ID_TAG = "SubsystemDeviceID"
XML_SUB_VENDOR_ID_TAG = "SubsystemVendorID"

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
            img_hash = xml_find_single_tag (img, XML_IMAGE_HASH_TAG, xml_file)
            image["hash"] = binascii.a2b_hex (re.sub ("\s", "", img_hash.text.strip ()))

            hash_type = xml_find_single_tag (img, XML_IMAGE_HASH_TYPE_TAG, xml_file, False)
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

def process_cfm (root):
    """
    Process CFM XML and generate list of element and attribute values.

    :param root: XML to utilize

    :return List of CFM values, manifest version, boolean for whether XML is for an empty CFM
    """

    xml = {}
    xml["fw_list"] = []

    device_id = root.attrib.get(XML_ID_ATTRIB)

    if device_id is None:
        raise ValueError ("No Device ID provided")

    xml["device_id"] = device_id.strip ()

    for fw in root.findall (XML_FW_TAG):
        firmware = {}
        firmware["signed_imgs"] = []

        version = fw.attrib.get(XML_VERSION_ATTRIB)

        if version is None:
            raise ValueError ("No Firmware version provided for device: {0}".format (
                xml["device_id"]))

        firmware["version"] = version.strip ()

        for img in fw.findall (XML_IMG_TAG):
            image = {}

            digest = img.findall (XML_DIGEST_TAG)

            if not digest or len (digest) > 1:
                raise ValueError (
                    "Invalid number of Digest tags in device: {0}, firmware: {1}".format (
                        xml["device_id"], firmware["version"]))

            image["digest"] = binascii.a2b_hex (re.sub ("\s", "", digest[0].text.strip ()))

            action = img.findall (XML_FAILURE_ACTION_TAG)

            if not action or len (action) > 1:
                raise ValueError (
                    "Invalid number of FailureAction tags in device: {0}, firmware: {1}".format (
                        xml["device_id"], firmware["version"]))

            image["failure_action"] = action[0].text.strip ()

            firmware["signed_imgs"].append (image)

        if not firmware["signed_imgs"]:
            raise ValueError ("No signed images found for device: {0}, firmware: {1}".format (
                xml["device_id"], firmware["version"]))

        xml["fw_list"].append (firmware)

    if not xml["fw_list"]:
        raise ValueError ("No firmware found for device: {0}".format (xml["device_id"]))

    return xml, manifest_types.VERSION_1, False

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
    if ports != None:
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
    if power_controller != None:
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
        if muxes != None:
            xml["power_controller"]["interface"]["muxes"] = {}

            for mux in muxes.findall (XML_MUX_TAG):
                level = xml_extract_attrib (mux, XML_LEVEL_ATTRIB, False, xml_file)

                result = xml_extract_single_value (mux, {"address": XML_ADDRESS_TAG,
                    "channel": XML_CHANNEL_TAG}, xml_file)

                result["address"] = int (result["address"], 16)

                xml["power_controller"]["interface"]["muxes"].update ({level:result})

    components = xml_find_single_tag (root, XML_COMPONENTS_TAG, xml_file, False)
    if components != None:
        xml["components"] = []

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
                if muxes != None:
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

            xml["components"].append (curr_component)

    return xml, manifest_types.VERSION_2, False

def load_and_process_xml (xml_file, xml_type):
    """
    Process XML and generate list of element and attribute values.

    :param xml_file: XML to utilize
    :param xml_type: Type of manifest

    :return List of manifest values, manifest version, boolean for whether XML is for an empty manifest
    """

    root = et.parse (xml_file).getroot ()

    if xml_type is manifest_types.PFM:
        return process_pfm (root, xml_file)
    elif xml_type is manifest_types.CFM:
        return process_cfm (root, xml_file)
    elif xml_type is manifest_types.PCD:
        return process_pcd (root, xml_file)
    else:
        raise ValueError ("Unknown XML type: {0}".format (xml_type))

def get_manifest_format (xml_file):
    root = et.parse (xml_file).getroot ()
    fw_type = xml_extract_attrib (root, XML_TYPE_ATTRIB, True, xml_file, False)
    return manifest_types.VERSION_1 if fw_type is None else manifest_types.VERSION_2

def get_manifest_version (xml_file):
    root = et.parse (xml_file).getroot ()
    return xml_extract_attrib (root, XML_VERSION_ATTRIB, True, xml_file, False)

def get_manifest_type (xml_file):
    root = et.parse (xml_file).getroot ()
    return xml_extract_attrib (root, XML_TYPE_ATTRIB, True,xml_file,  False)
