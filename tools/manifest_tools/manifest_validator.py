"""
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the MIT license.
"""

import argparse
import sys
from pathlib import Path
import xmlschema

def validate_xml(schema_type: str, xml_file: Path) -> bool:
    """Validate XML file against XSD schema.
    
    Args:
        schema_type: Type of schema (CFM, PFM, or PCD)
        xml_file: Path to XML file to validate
        
    Returns:
        True if validation successful, False otherwise
    """
    # Get schema path
    schemas_dir = Path(__file__).parent / "schemas"
    schema_path = schemas_dir / f"{schema_type.lower()}.xsd"
    
    if not schema_path.exists():
        print(f"Error: Schema file not found: {schema_path}", file=sys.stderr)
        return False
    
    if not xml_file.exists():
        print(f"Error: XML file not found: {xml_file}", file=sys.stderr)
        return False
    
    try:
        schema = xmlschema.XMLSchema11(schema_path)
        schema.validate(xml_file)
        print(f"Validation successful: {xml_file}")
        return True
    except xmlschema.XMLSchemaValidationError as e:
        print(f"Validation failed for {xml_file}: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Validate manifest XML file against XSD schema"
    )
    parser.add_argument(
        "schema_type",
        choices=["CFM", "PFM", "PCD"],
        help="Schema type to validate against"
    )
    parser.add_argument(
        "xml_file",
        type=Path,
        help="Path to XML file to validate"
    )
    
    args = parser.parse_args()
    
    success = validate_xml(args.schema_type, args.xml_file)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
