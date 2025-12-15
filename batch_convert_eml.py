#!/usr/bin/env python3
"""
Batch EML to JSON Converter
Converts all EML files in a directory to JSON format
"""

import json
import glob
from pathlib import Path
import argparse
from eml_to_json_converter import EMLToJSONConverter


def batch_convert(input_dir: str, output_dir: str, tenant_id: str, mailbox_id: str = None):
    """Convert all EML files in a directory to JSON"""
    
    # Create output directory if it doesn't exist
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    # Create converter
    converter = EMLToJSONConverter(tenant_id=tenant_id)
    
    # Find all EML files
    eml_files = glob.glob(f"{input_dir}/*.eml")
    
    if not eml_files:
        print(f"No EML files found in {input_dir}")
        return
    
    print(f"Found {len(eml_files)} EML files to convert")
    
    successful = 0
    failed = 0
    
    for eml_file in sorted(eml_files):
        try:
            # Convert EML to JSON
            json_data = converter.convert_eml_to_json(eml_file, mailbox_id)
            
            # Create output filename
            base_name = Path(eml_file).stem
            output_file = Path(output_dir) / f"{base_name}.json"
            
            # Save JSON
            with open(output_file, 'w') as f:
                json.dump(json_data, f, indent=2)
            
            print(f"✓ Converted: {Path(eml_file).name} → {output_file.name}")
            successful += 1
            
        except Exception as e:
            print(f"✗ Failed to convert {Path(eml_file).name}: {e}")
            failed += 1
    
    print(f"\nConversion complete:")
    print(f"  Successful: {successful}")
    print(f"  Failed: {failed}")


def main():
    parser = argparse.ArgumentParser(description='Batch convert EML files to JSON format')
    parser.add_argument('input_dir', help='Directory containing EML files')
    parser.add_argument('-o', '--output-dir', default='./json_output',
                        help='Output directory for JSON files (default: ./json_output)')
    parser.add_argument('-m', '--mailbox', help='Default mailbox ID for all files')
    parser.add_argument('-t', '--tenant', default="2a9c5f75-c7ee-4b9f-9ccc-626ddcbd786a",
                        help='Tenant ID')
    
    args = parser.parse_args()
    
    batch_convert(args.input_dir, args.output_dir, args.tenant, args.mailbox)


if __name__ == "__main__":
    main()