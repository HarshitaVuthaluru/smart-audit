"""Generic end-to-end integration test for another contract (OwnershipBug.sol)."""

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from static_analysis.parse_contract import analyze_contract
from llm_agents.agent_coordinator import AgentCoordinator
from llm_agents.config import ModelConfig
from llm_agents.ollama_client import validate_ollama_setup


def test_generic_contract():
    print("=== STARTING GENERIC TEST (OwnershipBug.sol) ===")

    target_file = PROJECT_ROOT / "Testing Sol contracts" / "OwnershipBug.sol"
    source_code = target_file.read_text(encoding="utf-8")

    function_details, call_graph, detector_results = analyze_contract(str(target_file))
    contract_info = {
        "function_details": function_details,
        "call_graph": call_graph,
        "source_code": source_code,
        "detector_results": detector_results,
        "target_contract": {"path": target_file.name},
        "contracts_dir": str(target_file),
    }

    model_config = ModelConfig(
        analyzer_model="qwen2.5-coder:7b",
        skeptic_model="qwen2.5-coder:7b",
        exploiter_model="qwen2.5-coder:7b",
        generator_model="qwen2.5-coder:7b",
        skip_poc_generation=True,
        secure_generation_attempts=3,
        ollama_request_timeout=180,
    )

    coordinator = AgentCoordinator(model_config=model_config, use_rag=True)
    analysis_results = coordinator.analyze_contract(
        contract_info, auto_run_config={"auto_run": False, "max_retries": 0}
    )
    vulnerabilities = analysis_results.get("rechecked_vulnerabilities", [])
    print(f"Confirmed vulnerabilities count: {len(vulnerabilities)}")
    for v in vulnerabilities:
        print(f"  - {v.get('vulnerability_type')} | affected: {v.get('affected_functions')}")

    def progress_cb(stage, message, detail):
        print(f"[{stage}] {message}: {detail}")

    generated_secure = coordinator.generator.generate_secure_contract(
        source_code, vulnerabilities, progress_callback=progress_cb
    )

    print("\n=== FINAL GENERATED SECURE CONTRACT (OwnershipBug.sol) ===")
    print(generated_secure)
    print("==========================================================")

    # Compile candidate with solc/forge to confirm syntax
    ok, err = coordinator.generator._compile_secure_solidity(generated_secure)
    if not ok:
        print(f"FAILURE: Secure output did not compile: {err}")
        return False

    print("SUCCESS: Generic secure generation compiled and passed validation!")
    return True


if __name__ == "__main__":
    success = test_generic_contract()
    sys.exit(0 if success else 1)
