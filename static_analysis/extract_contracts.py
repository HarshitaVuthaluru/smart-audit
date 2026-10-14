import json
import os
import re
import shutil
from pathlib import Path

def extract_contracts_from_json(input_file, output_dir=None):
    """
    Extracts Solidity contracts from a JSON file where each key is a filename
    and the value is an object with a 'content' field containing Solidity code.
    
    Args:
        input_file: Path to the JSON file containing contract code
        output_dir: Directory to extract contract files to (defaults to same directory as input)
        
    Returns:
        Dictionary mapping original filenames to extracted file paths
    """
    # Create output directory if needed
    if output_dir is None:
        output_dir = os.path.dirname(input_file)
        
    os.makedirs(output_dir, exist_ok=True)
    
    # Read the input file
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Try to parse as JSON
    try:
        contracts_data = json.loads(content)
        
        # Check if it's a JSON object with contract content
        if not isinstance(contracts_data, dict):
            print(f"JSON file doesn't contain contract data dictionary")
            return {}
            
        # Extract each contract and write to separate files
        extracted_files = {}
        for filename, data in contracts_data.items():
            if isinstance(data, dict) and 'content' in data:
                contract_content = data['content']
                output_path = os.path.join(output_dir, filename)
                
                # Create subdirectories if needed
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(contract_content)
                
                extracted_files[filename] = output_path
                print(f'Extracted: {output_path}')
            else:
                print(f'Warning: Skipping {filename} - invalid format')
        
        return extracted_files
        
    except json.JSONDecodeError:
        print(f'Error: Not a valid JSON file: {input_file}')
        return {}

def extract_main_contract(extracted_files):
    """
    Attempts to identify the main contract file from the extracted files
    based on heuristics (non-interface, non-library files).
    
    Args:
        extracted_files: Dictionary of extracted files
        
    Returns:
        Path to the main contract file, or None if not identified
    """
    if not extracted_files:
        return None
        
    # First look for files that don't have 'interface' or 'library' in the name
    # and don't start with 'I' (common interface naming convention)
    main_candidates = []
    
    for filename, filepath in extracted_files.items():
        name_lower = filename.lower()
        
        # Skip interfaces and libraries
        if (name_lower.startswith('i') and name_lower[1:2].isupper()) or \
           'interface' in name_lower or 'library' in name_lower:
            continue
            
        main_candidates.append(filepath)
    
    # If we found candidates, return the first one
    if main_candidates:
        return main_candidates[0]
        
    # Otherwise, just return the first file
    return next(iter(extracted_files.values()))

def process_contract_file(filepath):
    """
    Process a contract file, extracting Solidity code if it's a JSON file.
    
    Args:
        filepath: Path to the contract file
        
    Returns:
        tuple: (processed_filepath, temp_dir)
        where processed_filepath is the path to the main contract file,
        and temp_dir is the path to a temporary directory containing extracted files
    """
    # Check if it looks like a JSON file
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content_sample = f.read(min(1000, os.path.getsize(filepath)))
        
        # Check if it looks like a JSON contract bundle
        if content_sample.strip().startswith('{') and '"content":' in content_sample:
            print("Detected JSON contract bundle, extracting...")
            
            # Use the parent directory if this is already in a _contracts directory
            parent_dir = os.path.dirname(filepath)
            if "_contracts" in parent_dir:
                temp_dir = parent_dir
            else:
                # Otherwise create a new _contracts directory
                temp_dir = os.path.splitext(filepath)[0] + '_contracts'
                
            os.makedirs(temp_dir, exist_ok=True)
            
            # Extract the full content
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse JSON
            contracts_data = json.loads(content)
            
            # Extract each contract file
            extracted_files = {}
            for filename, data in contracts_data.items():
                if isinstance(data, dict) and 'content' in data:
                    contract_content = data['content']
                    output_path = os.path.join(temp_dir, filename)
                    
                    # Create subdirectories if needed
                    os.makedirs(os.path.dirname(output_path), exist_ok=True)
                    
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write(contract_content)
                    
                    extracted_files[filename] = output_path
                    print(f'Extracted: {output_path}')
            
            if extracted_files:
                # Find a non-interface contract file
                main_candidates = []
                for filename, filepath in extracted_files.items():
                    if not filename.lower().startswith('i') and 'interface' not in filename.lower():
                        main_candidates.append(filepath)
                
                if main_candidates:
                    return main_candidates[0], temp_dir
                
                # If no main candidates, return the first file
                return next(iter(extracted_files.values())), temp_dir
    except Exception as e:
        print(f'Error processing contract file: {e}')
    
    # If not a JSON file or extraction failed, return the original file
    return filepath, None

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print('Usage: python extract_contracts.py <contract_json_file> [output_directory]')
        sys.exit(1)
        
    input_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else None
    
    extracted = extract_contracts_from_json(input_file, output_dir)
    if extracted:
        main_contract = extract_main_contract(extracted)
        if main_contract:
            print(f'Main contract identified: {main_contract}')
        else:
            print('Could not identify main contract')
    else:
        print('No contracts extracted')
