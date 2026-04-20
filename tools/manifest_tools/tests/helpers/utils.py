"""
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the MIT license.
"""
import re

# Helper to create a temporary config file
def create_temp_config(tmp_path, xml_files, output_file, key_file=None, config_template=None):
    config_lines = []
    if config_template:
        config_lines.extend(config_template)
    for xml in xml_files:
        config_lines.append(xml)
    config_lines.append(f"Output={output_file}")
    if key_file:
        config_lines.append(f"Key={key_file}")
    config_path = tmp_path / "manifest_test.config"
    config_path.write_text("\n".join(config_lines))
    return str(config_path)

# Helper to generate regex
def xsd_unexpected_child_regex(unexpected_tag, expected_tag=None, path=None):
    # DOTALL via (?s) so ".*" matches newlines in the xmlschema dump
    parts = [rf"Reason:\s+Unexpected child with tag\s+'{re.escape(unexpected_tag)}'"]
    if expected_tag:
        parts.append(rf"Tag\s+'{re.escape(expected_tag)}'\s+expected")
    if path:
        parts.append(rf"Path:\s+{re.escape(path)}")
    return r"(?s).*" + r".*".join(parts) + r".*"
