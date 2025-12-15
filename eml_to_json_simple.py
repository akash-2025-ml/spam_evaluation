#!/usr/bin/env python3
"""
Simple EML to JSON Converter
Takes EML file path as input and saves JSON to a text file
"""

import json
import os
from eml_to_json_converter import EMLToJSONConverter


def main():
    # Get EML file path from user
    eml_path = input("Enter the path to the EML file: ").strip()
    
    # Check if file exists
    if not os.path.exists(eml_path):
        print(f"Error: File '{eml_path}' not found!")
        return
    
    if not eml_path.lower().endswith('.eml'):
        print("Error: File must have .eml extension!")
        return
    
    # Create converter
    converter = EMLToJSONConverter()
    
    try:
        # Convert EML to JSON
        print(f"Converting {eml_path}...")
        json_data = converter.convert_eml_to_json(eml_path)
        
        # Create output filename (replace .eml with .txt)
        output_path = eml_path.rsplit('.', 1)[0] + '_converted.txt'
        
        # Save to text file
        with open(output_path, 'w') as f:
            json.dump(json_data, f, indent=2)
        
        print(f"✓ Successfully converted!")
        print(f"✓ JSON saved to: {output_path}")
        
    except Exception as e:
        print(f"Error converting file: {e}")


if __name__ == "__main__":
    main()