"""
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the MIT license.
"""

"""
PFM generator/parsing tests.

These tests validate the end-to-end PFM flow by invoking `pfm_generator.main()` directly:
1) Build a temporary generator config via `helpers.utils.create_temp_config`.
2) Generate a signed PFM binary into `tmp_path`.
3) Parse the generated blob and validate header/hashes/signature.
4) Convert the manifest to a Python tree and compare against the expected structure.

Required input files are checked into this repository:
  - PFM XML input:
      * tools/manifest_tools/pfm.xml
  - Signing key (test/dev key):
      * core/testing/keys/rsapriv.pem

How to run (from repo root):
  - Run this test module:
      pytest tools/manifest_tools/tests/test_manifest_pfm_generator.py
  - Run all manifest_tools tests:
      pytest tools/manifest_tools
  - Run a single test:
      pytest tools/manifest_tools/tests/test_manifest_pfm_generator.py::test_pfm_valid
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

from manifest_common import PFM_V2_MAGIC_NUM
from pfm_generator import main as pfm_gen

CERBERUS_DIR = Path(__file__).resolve().parent.parent.parent.parent
PFM_XML_DIR = CERBERUS_DIR / "tools/manifest_tools"
TEST_KEY = CERBERUS_DIR / "core/testing/keys" / "rsapriv.pem"

global_config_template = [
    "ID=1",
    "KeyType=RSA",
    "HashType=SHA256",
    "MaxRWSections=3"
]

def test_pfm_valid(tmp_path):
    xml_file = PFM_XML_DIR / "pfm.xml"
    output_file = tmp_path / "output_pfm.bin"
    config_file = create_temp_config(tmp_path, [str(xml_file)], str(output_file), str(TEST_KEY), global_config_template)
    pfm_gen([config_file])
    assert output_file.exists()
    m = load_manifest_blob(output_file)
    assert_header(m, magic=PFM_V2_MAGIC_NUM)
    assert_hashes_valid(m)
    assert_signature_valid(m, str(TEST_KEY))
    manifest_tree = manifest_to_tree(m)
    valid_tree = {
        "platform_id": "Server-BMC",
        "unused_byte": 0xFF,
        "fw_count" : 0x1,
        "fw_list" : [
            {
                "fw_id": "BMC",
                "fw_flags": 0,
                "version_count": 1,
                "versions": [
                    {
                        "version": "1.00.0",
                        "version_addr": 0x1,
                        "rw_regions": [
                            {"start_addr": 0x00050000, "end_addr": 0x000FFFFF, "flags": 0x1},
                            {"start_addr": 0x00F00000, "end_addr": 0x00FFFFFF, "flags": 0x0},
                        ],
                        "images": [
                            {
                                "regions": [
                                    {"start": 0x00000000, "end": 0x0004FFFF},
                                    {"start": 0x00100000, "end": 0x00EFFFFF},
                                ],
                                "hash": b"\xaa" * 32,  # 32 bytes of 0xAA
                                "hash_type": 0x0,
                                "flags": 0x1,
                            }
                        ]
                    }
                ]
            }
        ]
    }
    assert manifest_tree == valid_tree, "Manifest structure does not match"

# List of malformed XML test cases: (case_name, xml_content, expected_error_match)
malformed_cases = [
    (
        "malformed_readwrite_not_valid",
        """<Firmware type="BMC" platform="Server-BMC" version="1.00.0">
            <VersionAddr>0x00000001</VersionAddr>
            <RuntimeUpdate>false</RuntimeUpdate>
            <ReadWrite>
                <Port1/>
            </ReadWrite>
        </Firmware>""",
        xsd_unexpected_child_regex(unexpected_tag="Port1", expected_tag="Region", path="/Firmware/ReadWrite")
    ),
    (
        "malformed_signedimage_not_valid",
        """<Firmware type="BMC" platform="Server-BMC" version="1.00.0">
            <VersionAddr>0x00000001</VersionAddr>
            <RuntimeUpdate>false</RuntimeUpdate>
            <SignedImage>
                <Port2/>
            </SignedImage>
        </Firmware>""",
        xsd_unexpected_child_regex(unexpected_tag="Port2", expected_tag="Region", path="/Firmware/SignedImage")
    )
]

@pytest.mark.parametrize("case_name, xml_content, expected_error_match", malformed_cases)
def test_pfm_malformed_cases(tmp_path, case_name, xml_content, expected_error_match):
    """
    Parametrised test for malformed PFM XML cases.
    Each test writes XML content to a temp file and expects ValueError.
    """
    xml_file = tmp_path / f"{case_name}.xml"
    xml_file.write_text(xml_content)
    output_file = tmp_path / "output_pfm.bin"
    config_file = create_temp_config(tmp_path, [str(xml_file)], str(output_file), str(TEST_KEY), global_config_template)

    with pytest.raises(ValueError, match=expected_error_match):
        pfm_gen([config_file])
