"""
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the MIT license.
"""

"""
CFM generator/parsing tests.

These tests validate the end-to-end CFM flow by invoking `cfm_generator.main()` directly:
1) Build a temporary generator config via `helpers.utils.create_temp_config`.
2) Generate a CFM binary into `tmp_path`.
3) Parse the generated blob and validate header/hashes/signature.
4) Convert the manifest to a Python tree and compare against the expected structure.

Test inputs are checked into this repo and referenced by path:
  - XML inputs:
      * tools/testing/test_xml/cfm_component_measurement_data_first.xml
      * tools/testing/test_xml/cfm_empty.xml
      * tools/manifest_tools/cfm.xml
  - Component map:
      * tools/manifest_tools/component_map.json
  - Signing key (test/dev key):
      * core/testing/keys/rsapriv.pem

How to run (from repo root):
  - Run this test module:
      pytest tools/manifest_tools/tests/test_manifest_cfm_generator.py
  - Run all manifest_tools tests:
      pytest tools/manifest_tools
  - Run a single test:
      pytest tools/manifest_tools/tests/test_manifest_cfm_generator.py::test_cfm_measurement_data_first_valid
"""

from pathlib import Path
import pytest
import sys
from helpers.manifest_blob_parse import load_manifest_blob, manifest_to_tree
from helpers.manifest_blob_assert import (
    assert_header, assert_hashes_valid, assert_signature_valid
)
from helpers.utils import create_temp_config
from helpers.utils import xsd_unexpected_child_regex

sys.path.append(str(Path(__file__).resolve().parent.parent))

from manifest_common import CFM_MAGIC_NUM
from cfm_generator import main as cfm_gen

CERBERUS_DIR = Path(__file__).resolve().parent.parent.parent.parent
CFM_XML_DIR = CERBERUS_DIR / "tools/testing/test_xml"
COMPONENT_JSON = Path(__file__).resolve().parent.parent / "component_map.json"
CFM_XML = Path(__file__).resolve().parent.parent / "cfm.xml"
TEST_KEY = CERBERUS_DIR / "core/testing/keys" / "rsapriv.pem"

global_config_template = ["ID=1", "KeyType=RSA", "HashType=SHA256", "ComponentMap=" + str(COMPONENT_JSON), "CFM=" + str(CFM_XML)]

def test_cfm_measurement_data_first_valid(tmp_path):
    xml_file = CFM_XML_DIR / "cfm_component_measurement_data_first.xml"
    output_file = tmp_path / "output_cfm.bin"
    config_file = create_temp_config(tmp_path, [str(xml_file)], str(output_file), str(TEST_KEY), global_config_template)
    cfm_gen([config_file])
    assert output_file.exists()
    m = load_manifest_blob(output_file)
    assert_header(m, magic=CFM_MAGIC_NUM, sig_len=256)
    assert_hashes_valid(m)
    assert_signature_valid(m, str(TEST_KEY))
    manifest_tree = manifest_to_tree(m)
    valid_tree = {
        'platform_id': 'SKU1',
        'components': [{
            'attestation_protocol': 0,
            'slot_num': 1,
            'transcript_hash_type': 1,
            'measurement_hash_type': 0,
            'component_id': 3,
            'root_ca_digests': {
                'allowable_digests': [
                    b'\xee' * 32,
                    b'\xff' * 32
                ]
            },
            'pmr': {
                1: {'initial_value': b'\x11' * 32},
                2: {'initial_value': b'"' * 32}
            },
            'pmr_digests': {
                0: {'allowable_digests': [b'\xaa' * 32, b'\xbb' * 32]},
                4: {'allowable_digests': [b'\xcc' * 32]}
            },
            'measurements': {
                1: {
                    2: {'allowable_digests': [b'\xdd' * 32, b'\xee' * 32]}
                },
                2: {
                    2: {'allowable_digests': [b'\xcc' * 32]}
                }
            },
            'measurement_data': {
                1: {
                    2: {
                        'allowable_data': [
                            {
                                'data': [b'Test1', b'Test2'],
                                'bitmask': b'\x00\xff\x00\xff\xff\x00',
                                'bitmask_length': 6,
                                'check': 0,
                                'endianness': 1
                            },
                            {
                                'data': [b'\x00\x00"\x00\x00'],
                                'bitmask': b'\x00\x00\xff\x00\x00',
                                'bitmask_length': 5,
                                'check': 4,
                                'endianness': 0
                            }
                        ]
                    },
                    4: {
                        'allowable_data': [
                            {
                                'data': [b'eC'],
                                'bitmask': b'\x00\xff',
                                'bitmask_length': 2,
                                'check': 1,
                                'endianness': 0
                            },
                            {
                                'data': [b'\x10\x11'],
                                'check': 1,
                                'endianness': 1
                            }
                        ]
                    }
                }
            },
            'allowable_pfm': {
                1: {
                    'manifest_id': [
                        {'check': 0, 'endianness': 0, 'ids': [153, 154]},
                        {'check': 4, 'endianness': 0, 'ids': [157]}
                    ],
                    'platform': 'platformA'
                },
                2: {
                    'manifest_id': [{'check': 3, 'endianness': 0, 'ids': [85]}],
                    'platform': 'platformB'
                }
            },
            'allowable_cfm': {
                1: {
                    'manifest_id': [{'check': 4, 'endianness': 1, 'ids': [18]}],
                    'platform': 'platformC'
                },
                2: {
                    'manifest_id': [{'check': 0, 'endianness': 0, 'ids': [171]}],
                    'platform': 'platformE'
                }
            },
            'allowable_pcd': {
                'manifest_id': [{'check': 3, 'endianness': 0, 'ids': [52]}],
                'platform': 'platformD'
            }
        }]
    }
    assert manifest_tree == valid_tree, "Manifest structure does not match"

def test_cfm_empty_valid(tmp_path):
    output_file = tmp_path / "output_cfm.bin"
    config_file = create_temp_config(tmp_path, [], str(output_file), str(TEST_KEY),
                                      ["ID=1", "KeyType=RSA", "HashType=SHA384", "ComponentMap=" + str(COMPONENT_JSON),
                                       "CFM=" + str(CFM_XML_DIR / "cfm_empty.xml")])
    cfm_gen([config_file])
    assert output_file.exists()
    m = load_manifest_blob(output_file)
    assert_header(m, magic=CFM_MAGIC_NUM, sig_len=256)
    assert_hashes_valid(m)
    assert_signature_valid(m, str(TEST_KEY))
    manifest_tree = manifest_to_tree(m)
    valid_tree = {
        'platform_id': 'SKU1',
        'components': []
    }
    assert manifest_tree == valid_tree, "Manifest structure does not match"

# List of malformed XML test cases: (case_name, xml_content, expected_error_match)
malformed_cases = [
    (
        "malformed_measurement_not_valid",
        """<CFMComponent type="Component1" attestation_protocol="Cerberus" slot_num="1" transcript_hash_type="SHA384" measurement_hash_type="SHA384">
            <Measurement pmr_id="0" measurement_id="1">
                <AllowableData>
                    <Endianness>BigEndian</Endianness>
                    <Check>Equal</Check>
                    <Data>11111111111111111111111111111111</Data>
                    <Bitmask>11111111111111111111111111111111</Bitmask>
                </AllowableData>
            </Measurement>
        </CFMComponent>""",
        xsd_unexpected_child_regex(unexpected_tag="AllowableData", expected_tag="Digest", path="/CFMComponent/Measurement")
    ),
    (
        "malformed_measurementdata_not_valid",
        """<CFMComponent type="Component1" attestation_protocol="Cerberus" slot_num="1" transcript_hash_type="SHA384" measurement_hash_type="SHA384">
            <MeasurementData pmr_id="0" measurement_id="2">
                <Digest>111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111</Digest>
            </MeasurementData>
        </CFMComponent>""",
        xsd_unexpected_child_regex(unexpected_tag="Digest", expected_tag="AllowableData", path="/CFMComponent/MeasurementData")
    ),
    (
        "malformed_allowablepfm_not_valid",
        """<CFMComponent type="Component1" attestation_protocol="Cerberus" slot_num="1" transcript_hash_type="SHA384" measurement_hash_type="SHA384">
            <AllowablePFM port="1" platform="platformA">
                <Digest>111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111</Digest>
            </AllowablePFM>
            <Measurement pmr_id="0" measurement_id="1">
                <Digest>111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111</Digest>
            </Measurement>
        </CFMComponent>""",
        xsd_unexpected_child_regex(unexpected_tag="Digest", expected_tag="ManifestID", path="/CFMComponent/AllowablePFM")
    ),
    (
        "malformed_allowablecfm_not_valid",
        """<CFMComponent type="Component1" attestation_protocol="Cerberus" slot_num="1" transcript_hash_type="SHA384" measurement_hash_type="SHA384">
            <AllowableCFM index="1" platform="platformC">
                <Digest>111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111</Digest>
            </AllowableCFM>
            <Measurement pmr_id="0" measurement_id="1">
                <Digest>111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111</Digest>
            </Measurement>
        </CFMComponent>""",
        xsd_unexpected_child_regex(unexpected_tag="Digest", expected_tag="ManifestID", path="/CFMComponent/AllowableCFM")
    ),
    (
        "malformed_allowablepcd_not_valid",
        """<CFMComponent type="Component1" attestation_protocol="Cerberus" slot_num="1" transcript_hash_type="SHA384" measurement_hash_type="SHA384">
            <AllowablePCD platform="platformD">
                <Digest>111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111</Digest>
            </AllowablePCD>
            <Measurement pmr_id="0" measurement_id="1">
                <Digest>111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111</Digest>
            </Measurement>
        </CFMComponent>""",
        xsd_unexpected_child_regex(unexpected_tag="Digest", expected_tag="ManifestID", path="/CFMComponent/AllowablePCD")
    )
]

@pytest.mark.parametrize("case_name, xml_content, expected_error_match", malformed_cases)
def test_cfm_malformed_cases(tmp_path, case_name, xml_content, expected_error_match):
    """
    Parametrised test for malformed CFM XML cases.
    Each test writes XML content to a temp file and expects ValueError.
    """
    xml_file = tmp_path / f"{case_name}.xml"
    xml_file.write_text(xml_content)
    output_file = tmp_path / "output_cfm.bin"
    config_file = create_temp_config(tmp_path, [str(xml_file)], str(output_file), str(TEST_KEY), global_config_template)

    with pytest.raises(ValueError, match=expected_error_match):
        cfm_gen([config_file])

