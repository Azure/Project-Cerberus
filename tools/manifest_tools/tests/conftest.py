"""
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the MIT license.
"""

"""
Pytest configuration for manifest_tools tests.

Responsibilities:
  * Add the ``manifest_tools`` directory (the parent of ``tests/``) to
    ``sys.path`` so test modules can import generator code directly
    (``manifest_common``, ``pcd_generator``, ``cfm_generator``,
    ``pfm_generator``, ...).
  * Expose path constants shared by every test module
    (``CERBERUS_DIR``, ``MANIFEST_TOOLS_DIR``, ``TEST_XML_DIR``,
    ``TEST_KEY``, ``COMPONENT_JSON``) so individual test files don't
    each re-derive them. Tests import these via ``from conftest import ...``.
"""

import sys
from pathlib import Path

# --- sys.path setup ---------------------------------------------------------
MANIFEST_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(MANIFEST_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(MANIFEST_TOOLS_DIR))


# --- Shared path constants --------------------------------------------------
# Repo root is two levels above ``manifest_tools/`` (i.e. cerberus/).
CERBERUS_DIR = MANIFEST_TOOLS_DIR.parent.parent

# Most checked-in test XMLs live here. PFM tests point ``PFM_XML_DIR``
# elsewhere themselves; everything else uses this.
TEST_XML_DIR = CERBERUS_DIR / "tools/testing/test_xml"

# Test/dev signing key shared by every generator test.
TEST_KEY = CERBERUS_DIR / "core/testing/keys" / "rsapriv.pem"

# Default component map used by PCD / CFM generators.
COMPONENT_JSON = MANIFEST_TOOLS_DIR / "component_map.json"

