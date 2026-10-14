import requests
import json
import re
from collections import defaultdict
import os
from dotenv import load_dotenv

load_dotenv()

BSCSCAN_API_KEY = os.getenv("BSCSCAN_API_KEY")
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")
BASESCAN_API_KEY = os.getenv("BASESCAN_API_KEY")
ARBISCAN_API_KEY = os.getenv("ARBISCAN_API_KEY")

def fetch_and_flatten_contract(
    network: str,
    contract_address: str,
    output_file: str = "contract_flat.sol",
    flatten: bool = True,
    save_separate: bool = True,
):
    explorers = {
        "ethereum": "https://api.etherscan.io/api",
        "bsc": "https://api.bscscan.com/api",
        "base": "https://api.basescan.org/api",
        "arbitrum": "https://api.arbiscan.io/api",
    }

    api_keys = {
        "ethereum": ETHERSCAN_API_KEY,
        "bsc": BSCSCAN_API_KEY,
        "base": BASESCAN_API_KEY,
        "arbitrum": ARBISCAN_API_KEY,
    }

    api_key = api_keys[network]

    if network not in explorers:
        raise ValueError("Unsupported network. Use: ethereum, bsc, polygon.")

    url = f"{explorers[network]}?module=contract&action=getsourcecode&address={contract_address}&apikey={api_key}"
    response = requests.get(url).json()

    if response["status"] != "1" or not response["result"]:
        raise Exception(
            "Failed to fetch contract source. Check contract address or API key."
        )

    contract_data = response["result"][0]
    source_code = contract_data["SourceCode"].strip()

    if source_code.startswith("{{"):
        try:
            parsed_code = json.loads(source_code[1:-1])  # Remove surrounding braces
            sources = parsed_code.get("sources", {})

            contract_parts = {file: data["content"] for file, data in sources.items()}

            print(f"Found {len(contract_parts)} contract parts.")
            print("Flattening...")

            sorted_contracts = order_contracts_by_references(contract_parts)

            combined_code = "\n\n".join(sorted_contracts)
            source_code = process_source_code(combined_code)
        except json.JSONDecodeError:
            raise Exception("Error parsing multi-file contract source.")
    else:
        source_code = process_source_code(source_code)

    # Save flattened contract file
    if flatten:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(source_code)
        print(f"Flattened contract saved to {output_file}")
    
    # Save separate contract files
    contract_files_map = {}
    if save_separate:
        # Get access to the original contract parts
        original_contract_parts = {}
        
        # Check if this was a multi-file contract
        contract_data = response["result"][0]
        original_source = contract_data["SourceCode"].strip()
        
        if original_source.startswith("{{"):
            # This is a multi-file contract
            try:
                parsed_code = json.loads(original_source[1:-1])  # Remove surrounding braces
                sources = parsed_code.get("sources", {})
                
                # Create directory for separate contract files
                output_dir = f"{os.path.splitext(output_file)[0]}_contracts"
                os.makedirs(output_dir, exist_ok=True)
                
                for file_path, data in sources.items():
                    # Process each contract file (optionally preserving imports)
                    content = data["content"]
                    processed_content = process_source_code(content, preserve_imports=True)
                    
                    # Determine file name and path, preserving directory structure
                    # Get just the file name for simple cases
                    file_name = os.path.basename(file_path)
                    if not file_name.endswith(".sol"):
                        file_name += ".sol"
                    
                    # For paths with directories, create the same structure
                    rel_path = file_path
                    if rel_path.startswith("/"):
                        rel_path = rel_path[1:]
                    
                    target_path = os.path.join(output_dir, rel_path)
                    if not target_path.endswith(".sol"):
                        target_path += ".sol"
                    
                    # Ensure directories exist
                    os.makedirs(os.path.dirname(target_path), exist_ok=True)
                    
                    # Write the individual contract file
                    with open(target_path, "w", encoding="utf-8") as f:
                        f.write(processed_content)
                    
                    contract_files_map[file_path] = target_path
                
                print(f"Separate contract files saved to {output_dir}")
            except json.JSONDecodeError as e:
                print(f"Error parsing multi-file contract source: {e}. Separate files not saved.")
        else:
            # This is a single-file contract
            output_dir = f"{os.path.splitext(output_file)[0]}_contracts"
            os.makedirs(output_dir, exist_ok=True)
            
            file_name = f"{contract_address}.sol"
            target_path = os.path.join(output_dir, file_name)
            
            with open(target_path, "w", encoding="utf-8") as f:
                f.write(source_code)
                
            contract_files_map[file_name] = target_path
            print(f"Single contract file saved to {target_path}")
    
    return contract_files_map


def order_contracts_by_references(contract_parts):
    from collections import defaultdict
    import re

    # Update the regex to also capture interfaces and libraries
    pattern = re.compile(
        r"(?:contract|interface|library)\s+(\w+)\s*(?:is\s+([^{]+))?\s*\{", re.MULTILINE
    )

    contract_to_file = {}
    file_dependencies = defaultdict(set)

    # First pass: map each identifier to its file
    for filename, content in contract_parts.items():
        for match in pattern.finditer(content):
            identifier = match.group(1)
            contract_to_file[identifier] = filename

    # Second pass: record file dependencies based on inheritance/implementation
    for filename, content in contract_parts.items():
        for match in pattern.finditer(content):
            identifier = match.group(1)
            parents = match.group(2)
            if parents:
                for parent in re.split(r"\s*,\s*", parents.strip()):
                    parent_file = contract_to_file.get(parent)
                    if parent_file and parent_file != filename:
                        file_dependencies[filename].add(parent_file)

    visited = set()
    ordered_sources = []

    def visit(file_node):
        if file_node in visited:
            return
        visited.add(file_node)
        for dep in file_dependencies.get(file_node, []):
            visit(dep)
        ordered_sources.append(contract_parts[file_node])

    for filename in contract_parts:
        if filename not in visited:
            visit(filename)

    return ordered_sources


def process_source_code(source_code: str, preserve_imports: bool = False) -> str:
    import re

    # Remove all import statements if not preserving them
    if not preserve_imports:
        source_code = re.sub(r"^\s*import\s+.*$", "", source_code, flags=re.MULTILINE)

    # Capture and remove SPDX license declarations (if any)
    spdx_pattern = re.compile(r"^\s*//\s*SPDX-License-Identifier:.*$", re.MULTILINE)
    spdx_matches = spdx_pattern.findall(source_code)
    source_code = spdx_pattern.sub("", source_code)
    spdx_header = spdx_matches[0].strip() if spdx_matches else ""

    # Capture and remove all pragma solidity declarations
    pragma_pattern = re.compile(r"^\s*pragma solidity.*?;\s*$", re.MULTILINE)
    pragma_matches = pragma_pattern.findall(source_code)
    source_code = pragma_pattern.sub("", source_code)
    pragma_header = pragma_matches[0].strip() if pragma_matches else ""

    # Build the header with only one SPDX and one pragma (if found)
    header = ""
    if spdx_header:
        header += spdx_header + "\n"
    if pragma_header:
        header += pragma_header + "\n"

    # Return header + cleaned source code
    return header + "\n" + source_code.strip()


# # Example usage
# output_path = os.path.join(
#     os.path.dirname(__file__), "..", "static_analysis", "test_contracts", "sample.sol"
# )
# # fetch_and_flatten_contract(
# #     "base",
# #     "0xd990094a611c3de34664dd3664ebf979a1230fc1",
# #     output_file=output_path,
# # )
