from slither import Slither
from slither.core.declarations.function import Function
from slither.core.declarations.contract import Contract
from slither.printers.abstract_printer import AbstractPrinter
from slither.solc_parsing.expressions.find_variable import SolidityFunction
from .slither_detectors import DETECTORS
from .call_graph_printer import PrinterCallGraphV2
from typing import Dict, List
from pathlib import Path
import json
import os
import re
from .extract_contracts import process_contract_file
from utils.function_identifiers import canonical_function_id


_PRAGMA_VERSION = re.compile(r"\bpragma\s+solidity\s+[^;]*?(0)\.(\d+)\.")


def _solc_for_source(filepath: str) -> tuple[str | None, str]:
    """Select the locally installed compiler compatible with a Solidity pragma.

    Phase 5 contracts remain on the existing global 0.8.20 compiler.  Legacy
    0.4.x sources use the separately installed 0.4.26 binary only for that
    Slither invocation; neither PATH nor the global compiler is changed.
    """
    try:
        source = Path(filepath).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None, "--via-ir --optimize"

    match = _PRAGMA_VERSION.search(source)
    if not match or int(match.group(2)) >= 5:
        return None, "--via-ir --optimize"

    legacy_solc = Path(r"C:\Solidity\solc-0.4.26\solc.exe")
    if not legacy_solc.is_file():
        raise RuntimeError(
            "Solidity 0.4.x source requires the local legacy compiler at "
            f"{legacy_solc}, but it is unavailable."
        )
    return str(legacy_solc), "--optimize"


def analyze_contract(filepath: str):
    """
    Analyzes a Solidity contract using Slither and returns:
    1. A list of function details (name, visibility, parameters, returns, etc.)
    2. A call graph mapping each function to the functions it calls
    """
    # Only add a remapping when the dependency is available locally.  The
    # previous absolute macOS path made Slither fail on every other machine.
    project_root = Path(__file__).resolve().parent.parent
    openzeppelin_dir = project_root / "node_modules" / "@openzeppelin"
    solc_remaps = []
    if openzeppelin_dir.is_dir():
        solc_remaps.append(f"@openzeppelin={openzeppelin_dir.as_posix()}")
    forge_std_dir = project_root / "exploit" / "lib" / "forge-std" / "src"
    if forge_std_dir.is_dir():
        solc_remaps.append(f"forge-std={forge_std_dir.as_posix()}")
    
    # Preprocess the contract file - check if it's a JSON bundle and extract if needed
    temp_dir = None
    try:
        # Process the file, potentially extracting contracts if it's a JSON bundle
        processed_filepath, temp_dir = process_contract_file(filepath)
        if processed_filepath != filepath:
            print(f"Preprocessed JSON contract: {filepath} -> {processed_filepath}")
            filepath = processed_filepath
    except Exception as e:
        print(f"Error preprocessing contract: {e}")
        # Continue with the original filepath
    
    # CryticCompile on Windows can misinterpret an absolute drive path as a
    # Solidity project path. Keep source metadata absolute, but give Slither a
    # path relative to the running project so uploaded contracts work in both
    # the analyzer and secure-generation flows.
    slither_target = filepath
    if os.name == "nt" and os.path.isabs(filepath):
        slither_target = os.path.relpath(filepath, os.getcwd())

    # Initialize Slither using a compiler compatible with the source pragma.
    # The legacy compiler is process-local to this invocation, so modern 0.8
    # analysis continues to use the existing global compiler unchanged.
    selected_solc, solc_args = _solc_for_source(filepath)
    slither_kwargs = {"solc_args": solc_args, "solc_remaps": solc_remaps}
    if selected_solc:
        slither_kwargs["solc"] = selected_solc
    slither = Slither(slither_target, **slither_kwargs)

    # slither = Slither(filepath)
    printer = PrinterCallGraphV2(slither, None)

    for detector_class in DETECTORS:
        slither.register_detector(detector_class)

    detectors_results = slither.run_detectors()
    cfg_data = printer.get_call_graph_content()
    all_function_details = []
    call_graph = cfg_data
    analysis_path = Path(filepath).resolve()
    analysis_root = analysis_path if analysis_path.is_dir() else analysis_path.parent

    # Iterate over each contract in the source
    for contract in slither.contracts:
        contract_name = contract.name
        source_mapping = contract.source_mapping
        source_file = (
            getattr(getattr(source_mapping, "filename", None), "absolute", None)
            if source_mapping
            else None
        )
        if source_file:
            source_path = Path(source_file).resolve()
            in_scope = source_path.is_relative_to(analysis_root) if analysis_path.is_dir() else source_path == analysis_path
            if not in_scope:
                continue

        # Iterate over each function in the contract
        # `functions` includes every inherited forge-std helper.  Only direct
        # declarations belong to the contract being audited.
        for func in contract.functions_declared:
            # Extract basic function info
            func_name = func.name
            # Exclude function if func_name == constructor
            if func_name.startswith("slitherConstructor"):
                continue

            visibility = str(func.visibility)  # e.g. 'public', 'external', ...
            parameters = [(str(p.type), p.name) for p in func.parameters]
            returns = [(str(r.type), r.name) for r in func.returns]

            # Lines of code (start_line, end_line). Not all functions have source mappings, handle None carefully.
            # Slither's `start`/`end` are character offsets, not source-line
            # numbers.  Use its line mapping so reports and prompts point to
            # the correct Solidity locations.
            lines = func.source_mapping.lines if func.source_mapping else []
            start_line = min(lines) if lines else None
            end_line = max(lines) if lines else None

            # Get functions being called
            called_functions = [
                call.name
                for call in func.internal_calls
                if not isinstance(call, SolidityFunction)
            ]

            # Prepare the function detail dict
            func_detail = {
                "contract": contract_name,
                "function": func_name,
                "function_id": canonical_function_id(func_name, parameters),
                "visibility": visibility,
                "parameters": parameters,
                "returns": returns,
                "start_line": start_line,
                "end_line": end_line,
                "called_functions": called_functions,
                "modifiers": [modifier.name for modifier in func.modifiers],
                "content": func.source_mapping.content if func.source_mapping else None,
            }

            all_function_details.append(func_detail)

    # Clean up temp directory if we created one
    if temp_dir and os.path.exists(temp_dir):
        print(f"Note: Temporary extracted files are in {temp_dir}")
        # We're not removing the directory to allow for inspection
        # import shutil
        # shutil.rmtree(temp_dir)
        
    return all_function_details, call_graph, detectors_results


if __name__ == "__main__":
    # Example usage:
    filepath = "/Users/advait/Desktop/NTU/fyp-fr/static_analysis/test_contracts/code.sol"  # Adjust path to your .sol file
    function_details, cg, detector_results = analyze_contract(filepath)

    # Print function details
    print("==== Function Details ====")
    for f in function_details:
        print(f"Contract: {f['contract']}")
        print(f"Function: {f['function']}")
        print(f"Visibility: {f['visibility']}")
        print(f"Parameters: {f['parameters']}")
        print(f"Returns: {f['returns']}")
        print(f"Lines: {f['start_line']} - {f['end_line']}")
        print()

    # Print call graph
    # Returns the Call Graph formatted for DOT files
    print("==== Call Graph ====")
    print(cg["all_contracts"])
