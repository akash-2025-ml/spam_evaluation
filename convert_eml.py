#!/usr/bin/env python3
"""
Simple EML to JSON Converter
Usage: python3 convert_eml.py <eml_file>
Output: Creates <eml_file_name>_output.txt
"""

import json
import sys
import os
from pathlib import Path
from eml_to_json_converter import EMLToJSONConverter


def main():
    # Check command line arguments
    if len(sys.argv) != 2:
        print("Usage: python3 convert_eml.py <eml_file>")
        print("Example: python3 convert_eml.py email.eml")
        print("\nThis will create email_output.txt with the JSON content")
        return 1
    
    # Get EML file path
    eml_path = sys.argv[1]
    
    # Validate file
    if not os.path.exists(eml_path):
        print(f"Error: File '{eml_path}' not found!")
        return 1
    
    if not eml_path.lower().endswith('.eml'):
        print("Error: File must have .eml extension!")
        return 1
    
    # Create output filename
    base_name = Path(eml_path).stem
    output_path = f"{base_name}_output.txt"
    
    # Create converter
    converter = EMLToJSONConverter()
    
    try:
        # Convert EML to JSON
        print(f"Converting '{eml_path}'...")
        json_data = converter.convert_eml_to_json(eml_path)
        
        # Save to text file
        with open(output_path, 'w') as f:
            json.dump(json_data, f, indent=2)
        
        print(f"✓ Successfully converted!")
        print(f"✓ Output saved to: {output_path}")
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())