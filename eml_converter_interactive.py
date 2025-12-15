#!/usr/bin/env python3
"""
Interactive EML to JSON Converter
Prompts user for input file and output file paths
"""

import json
import os
from eml_to_json_converter import EMLToJSONConverter


def main():
    print("=== EML to JSON Converter ===\n")
    
    # Get input EML file path
    while True:
        eml_path = input("Enter the path to the EML file: ").strip()
        
        if os.path.exists(eml_path):
            if eml_path.lower().endswith('.eml'):
                break
            else:
                print("Error: File must have .eml extension!")
        else:
            print(f"Error: File '{eml_path}' not found! Please try again.")
    
    # Automatically set output file path
    output_path = eml_path.rsplit('.', 1)[0] + '_output.txt'
    
    # Create converter
    converter = EMLToJSONConverter()
    
    try:
        # Convert EML to JSON
        print(f"\nConverting '{eml_path}'...")
        json_data = converter.convert_eml_to_json(eml_path)
        
        # Save to text file
        with open(output_path, 'w') as f:
            json.dump(json_data, f, indent=2)
        
        print(f"\n✓ Conversion successful!")
        print(f"✓ JSON saved to: {output_path}")
        print(f"✓ File size: {os.path.getsize(output_path):,} bytes")
        
    except Exception as e:
        print(f"\nError converting file: {e}")
        return 1
    
    print("\n✓ Done!")
    return 0


if __name__ == "__main__":
    exit(main())