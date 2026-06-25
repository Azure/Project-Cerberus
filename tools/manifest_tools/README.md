# Manifest Tools

This directory contains the Python generators used to build Cerberus manifest binaries from XML.

The main entry points are:

- `pfm_generator.py` for Platform Firmware Manifest (PFM) output
- `cfm_generator.py` for Component Firmware Manifest (CFM) output
- `pcd_generator.py` for Platform Configuration Data (PCD) output
- `manifest_validator.py` for XML/XSD validation

Supporting modules shared by all generators:

- `manifest_common.py` loads config files, loads signing keys, validates version consistency, and writes the final binary
- `manifest_parser.py` validates XML against the local XSD files in `schemas/` and converts XML into Python dictionaries
- `manifest_types.py` defines the manifest version constants

## Table of Contents

- [Working Directory](#working-directory)
- [Environment](#environment)
- [Running The Generators](#running-the-generators)
- [Config File Format](#config-file-format)
- [CFM Component Defaults](#cfm-component-defaults)
- [Generator-Specific Config Examples](#generator-specific-config-examples)
- [Manifest Version Control](#manifest-version-control)
- [General Script Flow](#general-script-flow)
- [XML Validation](#xml-validation)
- [Tests](#tests)
- [Practical Notes](#practical-notes)

## Working Directory

All commands in this README assume your current directory is `tools/manifest_tools`.

From the repository root:

```bash
cd tools/manifest_tools
```

The relative paths used in the examples in this README assume the standard `cerberus-core` style repository layout. If you are working from a mirrored or extracted tree, adjust paths like `../testing/test_xml/...` and `../../core/testing/keys/...` to match your local layout.

## Environment

Using a Python virtual environment is recommended but optional.

If you do not already have a local virtual environment in this directory, create one and activate it:

```bash
python3 -m venv venv
source ./venv/bin/activate
```

Then install the Python dependencies:

```bash
python3 -m pip install -r requirements.txt
```

## Running The Generators

```bash
python3 pfm_generator.py [pfm_generator.config]
python3 cfm_generator.py [cfm_generator.config]
python3 pcd_generator.py [pcd_generator.config]
```

If the config path is omitted, each script falls back to the matching default config file beside the script.
Those checked-in `*_generator.config` files are templates, not ready-to-run examples. They contain
placeholder paths like `/path/to/...`, so the no-argument form only works after you edit the
matching template or replace it with a real local config file.

PFM also supports two optional flags:

```bash
python3 pfm_generator.py my_pfm.config --bypass
python3 pfm_generator.py my_pfm.config --ignore_overlap
```

- `--bypass` generates a bypass-mode PFM with only header/platform data and no firmware policy sections.
- `--ignore_overlap` keeps generating the PFM even if flash regions overlap. During normal PFM v2 generation, the script always writes `overlap_warning.txt` next to the output binary when this flag is used; the file lists overlaps if any are found.

CFM also supports an optional aggregation flag:

```bash
python3 cfm_generator.py my_cfm.config --no-aggregation
```

- `--no-aggregation` disables measurement aggregation and emits all measurements as regular non-aggregated measurement entries.

CFM generation additionally requires a sibling `component_defaults.cfg` file next to `cfm_generator.py`. See CFM Component Defaults below.

## Config File Format

The config loader in `manifest_common.load_config()` uses a simple line-based format.

- Current parser behavior: supported `key=value` lines are parsed as config settings.
- Current parser behavior: other lines are treated as input XML paths.
- Comment lines are not recognized by the current parser, so they will be interpreted as paths.
- Avoid blank lines as well, since the current implementation does not treat them as comments or separators.
- Safe pattern: keep config files to supported `key=value` entries and XML paths only, one per line.

Example:

```ini
ID=1
KeyType=RSA
HashType=SHA256
/path/to/input_1.xml
/path/to/input_2.xml
Output=/path/to/output.bin
Key=/path/to/key.pem
KeySize=256
```

### Supported Keys

| Key | Requirement | Meaning | Used by |
| --- | --- | --- | --- |
| `ID` | Required for PFM and CFM; optional for PCD. | Output manifest ID. PCD falls back to the root XML `version` attribute when this is omitted. | PFM, CFM, PCD |
| `Output` | Required. | Output binary path. The parent directory is created automatically if needed. | PFM, CFM, PCD |
| `HashType` | Required. | Manifest hash algorithm: `SHA256`, `SHA384`, or `SHA512`. | PFM, CFM, PCD |
| `Key` | Optional. | Private signing key path. If omitted, the manifest is generated unsigned. | PFM, CFM, PCD |
| `KeyType` | Optional. | `RSA` or `ECC`. Only `ECC` is treated specially; anything else is handled as RSA. | PFM, CFM, PCD |
| `KeySize` | Optional. | Key size in bytes used when `Key` is omitted. Only RSA `384` or `512` and ECC `48` or `66` map to a defined non-zero header key strength. Other sizes, including RSA `256` and ECC `32`, leave key strength as `0`. When `Key` is present, the imported key size overrides this value. | PFM, CFM, PCD |
| `MaxRWSections` | Optional. | Maximum number of non-contiguous RW regions allowed after permutation/merge checks. Must be `<= 6`. Default is `3`. | PFM |
| `CFM` | Required for CFM. | Path to the CFM selection XML that chooses which component XMLs are included and what platform ID/format to use. | CFM |
| `ComponentMap` | Effectively required for CFM and PCD. | Path to a JSON map of component type string to component ID. If a new component type is encountered, the file is updated in place. | CFM, PCD |

### Input XML Lines

The plain path lines in the config are the source XML files:

- PFM: one or more firmware XML files
- CFM: zero or more component XML files. `cfm_generator.py` can generate an empty CFM if the selection XML has a platform SKU but no listed components and no component XML files are provided.
- PCD: exactly one XML file. `pcd_generator.py` calls `load_xmls(..., 1, manifest_types.PCD)`, so more than one XML path is rejected.

## CFM Component Defaults

`cfm_generator.py` reads an extra configuration file named `component_defaults.cfg` from the same directory as the script (`tools/manifest_tools/component_defaults.cfg`). This file is **required** for CFM generation. If it is missing, `cfm_generator.main()` raises `FileNotFoundError` and aborts before producing any output.

The file is parsed with the standard `configparser` module, so it uses INI syntax (one `[Section]` per component type, `key = value` entries below each section). Unlike the main `*_generator.config` file, comments (`#` and `;`) and blank lines are allowed here.

Recognised entries:

| Section | Key | Value | Meaning |
| --- | --- | --- | --- |
| `[defaults]` (case-insensitive) | _any_ | _any_ | Reserved — the whole `defaults` section is skipped by the loader. |
| `[<component-type>]` | `unique_measurement_id` | Integer in the range `1`–`239`. Decimal or `0x...` hex. Empty values are ignored. | Identifies the measurement ID that is guaranteed unique across every version of this component. The generator validates uniqueness across versions and moves the entry to the first position of the first PMR so it can act as a stable version identifier. |

Invalid values (non-integer, out of range, or component listed multiple times during loading) raise `ValueError`.

Behaviour for multi-version components:

- If a component has a matching `unique_measurement_id`, the chosen measurement (digest or data) is validated and reordered to the front.
- Multi-version components **not** covered by an explicit entry are still subject to an auto-check: the first measurement in their first PMR must be unique across all versions. If it is not, the generator aborts with an actionable error message that suggests adding a `unique_measurement_id` entry for that component.
- Single-version components and the empty-CFM path skip the uniqueness checks.

Minimal example:

```ini
# Identify a stable version-discriminator measurement per component.
[ComponentA]
unique_measurement_id = 1

[ComponentB]
unique_measurement_id = 0x1A
```

### Optional Diagnostics Environment Variable

`cfm_generator.py` also looks at the optional `COMPONENT_VERSION_STRINGS` environment variable. It is used purely to render human-readable version labels in the uniqueness diagnostic messages above; it never changes the produced binary.

Format: `COMPONENT_A:ver1,ver2,ver3;COMPONENT_B:ver1`.

- Component name and version list are separated by `:`.
- Multiple components are separated by `;`.
- Versions for a component are comma-separated and assigned to version numbers in order (first listed → version 1, second → version 2, ...).
- Malformed entries (missing `:`, empty component name, empty version list, duplicate component names) raise `ValueError`.

## Generator-Specific Config Examples

The examples below mirror the checked-in inputs used by the pytest suite. The only value adapted for normal manual use is `Output=`, which is shown as a local file in the current directory.

### PFM

```ini
ID=1
KeyType=RSA
HashType=SHA256
MaxRWSections=3
pfm.xml
Output=output_pfm.bin
Key=../../core/testing/keys/rsapriv.pem
```

### CFM

```ini
ID=1
KeyType=RSA
HashType=SHA256
ComponentMap=component_map.json
CFM=cfm.xml
../testing/test_xml/cfm_component_measurement_data_first.xml
Output=output_cfm.bin
Key=../../core/testing/keys/rsapriv.pem
```

Behavior worth knowing:

- The selection XML referenced by `CFM` sets the output platform ID through its `sku` attribute.
- A selected component is only emitted if its component XML is also listed in the `cfm_generator.config` file.
- Only component XMLs whose `type` matches a listed `<Component>` entry are included.
- Extra component XMLs that are not selected are ignored.

### PCD

```ini
KeyType=RSA
HashType=SHA256
ComponentMap=component_map.json
../testing/test_xml/pcd_sku_specific.xml
Output=output_pcd.bin
Key=../../core/testing/keys/rsapriv.pem
```

For PCD, omitting `ID=` is fine because the loader falls back to the root XML `version` attribute. For CFM and PFM, keep `ID=` in the config.

## Manifest Version Control

Version selection is controlled by the XML, not by the `.config` file.

### PFM

PFM uses two code paths:

- Version 1: the root `<Firmware>` element does not have a `type` attribute
- Version 2: the root `<Firmware>` element includes a `type` attribute

Examples:

```xml
<Firmware platform="Server-BMC" version="1.00.0">
```

```xml
<Firmware type="BMC" platform="Server-BMC" version="1.00.0">
```

There is no `format_version` attribute for PFM in the current flow.

### CFM

CFM format comes from the selection XML referenced by `CFM=`.

- Version 2: omit `format_version`, or set it to `2`
- Version 3: set `format_version="3"` on the root `<CFM ...>` element

Example:

```xml
<CFM sku="SKU1" format_version="3">
```

The component XML files themselves do not select the output format. The selection XML does.

Empty CFM manifests are an exception. If no component XML is processed, `manifest_common.load_xmls()` marks the manifest as empty and forces the output format to version 2 for backward compatibility.

### PCD

PCD format comes from the root `format_version` attribute:

- Version 2: omit `format_version`, or set it to `2`
- Version 3: set `format_version="3"`

Example:

```xml
<PCD sku="SKU1" version="0x1A" format_version="3">
```

### Why Version 3 Matters

`manifest_common.generate_manifest()` only allows table-of-contents extensions when the manifest version is 3. In practice, that means very large manifests with more than 255 elements need version 3.

## General Script Flow

All three generators follow the same high-level pattern:

1. Call `manifest_common.load_xmls()`, which reads the `.config` file through `manifest_common.load_config()`.
2. Load settings such as signing key info, `ComponentMap`, `MaxRWSections`, and, for CFM, the selection XML referenced by `CFM=`.
3. Validate each plain input XML path from the config against the corresponding XSD in `schemas/`. The CFM selection XML is parsed separately and is not schema-validated during generation.
4. Parse the XML into Python dictionaries with `manifest_parser.py`.
5. Check that all input XMLs in the run resolve to a consistent manifest version.
6. Build the manifest element list in generator-specific code.
7. Generate the manifest header, TOC, hashes, and optional signature.
8. Write the output binary to the configured path.

### PFM Flow

`pfm_generator.py` then does the following:

1. Read all firmware XMLs listed in the config.
2. If the XML resolves to PFM version 1, dispatch to `pfm_generator_v1.py` and skip the PFM v2-only steps below.
3. For PFM version 2, group firmware XMLs by firmware type and version.
4. Build RW region and signed-image structures for each version.
5. Check for overlapping regions.
6. Check the effective number of RW sections against `MaxRWSections`.
7. Generate either:
   - a normal PFM with firmware policy sections, or
   - a bypass-mode PFM if `--bypass` is used.

### CFM Flow

`cfm_generator.py` then does the following:

1. Read the selection XML from the `CFM=` config line.
2. Read all component XML files listed in the config.
3. Keep only component XMLs whose `type` appears in the selection XML.
4. Group repeated component definitions into version sets on a per-component basis.
5. Consolidate identical measurement and measurement-data entries into version set `0`.
6. Load `component_defaults.cfg` and, for each multi-version component with an explicit `unique_measurement_id`, validate that the chosen measurement is unique across versions and move it to the first position of the first PMR.
7. Auto-check that the first measurement of every remaining multi-version component is unique across versions. If it is not, the generator aborts and suggests adding a `unique_measurement_id` entry in `component_defaults.cfg`.
8. Generate platform ID, component-device entries, PMRs, digests, measurement blocks, allowable manifest blocks, and root CA digests.
9. Use `ComponentMap` to resolve string component types to numeric component IDs.

Measurement element ordering inside each component is decided by the per-component `unique_measurement_is_digest` / `unique_measurement_is_data` flags set by the uniqueness step. When neither flag is set, the original `unique` field from the XML is used as the backward-compatible fallback.

### PCD Flow

`pcd_generator.py` then does the following:

1. Read a single PCD XML.
2. Build the platform ID element.
3. Build optional power-controller data.
4. Generate the component list and collect timeout values.
5. Generate optional SPI flash port data.
6. Generate the final RoT element using the collected component count, port count, and timeout values.
7. Use `ComponentMap` to resolve or create numeric component IDs.

## XML Validation

To validate XML without generating a binary:

```bash
python3 manifest_validator.py PFM path/to/pfm.xml
python3 manifest_validator.py CFM path/to/file.xml
python3 manifest_validator.py PCD path/to/pcd.xml
```

The validator uses the same XSDs under `schemas/` as the generators.

## Tests

The manifest-tool test suite lives in `tests/` and provides end-to-end coverage for the generators.

Current test modules:

- `test_manifest_pfm_generator.py`
- `test_manifest_cfm_generator.py`
- `test_manifest_pcd_generator.py`

### What The Tests Cover

Each test module follows the same pattern:

1. Build a temporary generator config file with `helpers.utils.create_temp_config()`.
2. Call the real generator entry point directly:
   - `pfm_generator.main()`
   - `cfm_generator.main()`
   - `pcd_generator.main()`
3. Generate the output binary into pytest's `tmp_path`.
4. Parse the generated binary back into a Python structure.
5. Validate header fields, hashes, and signatures.
6. Compare the parsed manifest tree against the expected structure.

The tests also include malformed XML cases to confirm that XSD validation failures are surfaced with useful error messages.

### Helper Modules

Shared test setup lives in `tests/conftest.py`, and the rest of the helper code is in `tests/helpers/`:

- `conftest.py` exposes shared path constants (`CERBERUS_DIR`, `MANIFEST_TOOLS_DIR`, `TEST_XML_DIR`, `TEST_KEY`, `COMPONENT_JSON`) and inserts `tools/manifest_tools/` on `sys.path` so test modules can import the generators directly
- `utils.py` creates temporary config files and builds regexes for XSD error matching
- `manifest_blob_parse.py` reads a generated manifest binary and converts it into a Python tree, including TOC-extension traversal and PCD v3 / TCGLog component decoding
- `manifest_blob_assert.py` verifies header fields, hash integrity, and signatures

### Test Inputs

The tests use checked-in XML and key material from the repository:

- sample manifest XMLs in the current directory
- additional XML fixtures under `../testing/test_xml/`
- component ID map at `component_map.json`
- signing key at `../../core/testing/keys/rsapriv.pem`

Because the tests generate their config files dynamically, you usually do not need to edit any checked-in `.config` files to add or update coverage.

### Running The Tests

The commands below assume you are in `tools/manifest_tools`.

Run all manifest tool tests:

```bash
pytest
```

Run a single module:

```bash
pytest tests/test_manifest_pfm_generator.py
pytest tests/test_manifest_cfm_generator.py
pytest tests/test_manifest_pcd_generator.py
```

Run a single test case:

```bash
pytest tests/test_manifest_cfm_generator.py::test_cfm_measurement_data_first_valid
```

### General Test Flow

PFM tests validate that:

- the generator accepts a temporary config and sample XML
- the output header matches the PFM magic number
- the generated hashes and signature are correct
- the parsed firmware/version/RW/image tree matches the expected structure

CFM tests validate that:

- the selection XML and component XMLs are combined correctly
- per-component version-set grouping works
- empty CFM generation works when the selection XML contains no components
- hashes and signatures are valid

PCD tests validate that:

- RoT, ports, power controller, and components are encoded correctly
- empty PCD generation works
- the parsed tree matches the expected platform structure
- hashes and signatures are valid

### Adding A New Test

The existing tests are a good template for new cases:

1. Pick the generator module you want to cover.
2. Add a new XML fixture under `tools/testing/test_xml/` or reuse an existing one.
3. Build a temporary config with `create_temp_config(...)`.
4. Call the generator's `main([...])` function.
5. Parse the output with `load_manifest_blob(...)` and `manifest_to_tree(...)`.
6. Assert the expected binary header and Python tree.

For schema failures, add a malformed XML string and assert the raised error with `pytest.raises(...)`.

### Tips

- These are end-to-end tests, so they are the best place to verify config parsing, XML parsing, manifest construction, and signing together.
- When debugging a failure, it is often easiest to run one test with `-vv` and keep the generated output under `tmp_path` by reproducing the same config manually.

## Practical Notes

- If `Key=` is omitted, the scripts generate an unsigned manifest.
- `ComponentMap` is not just read-only metadata. New component types are appended to the JSON file.
- CFM generation requires the selection XML even if you want an empty output.
- CFM generation also requires `component_defaults.cfg` to exist next to `cfm_generator.py`.
