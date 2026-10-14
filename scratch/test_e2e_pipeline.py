"""End-to-end integration test for the secure contract generation pipeline."""

import os
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from static_analysis.parse_contract import analyze_contract
from llm_agents.agent_coordinator import AgentCoordinator
from llm_agents.config import ModelConfig
from llm_agents.ollama_client import validate_ollama_setup


def run_e2e_test():
    print("=== STARTING END-TO-END PIPELINE TEST ===")

    # 1. Check Ollama setup
    is_ready, err = validate_ollama_setup(["qwen2.5-coder:7b"])
    if not is_ready:
        print(f"Ollama not ready: {err}")
        return False

    # 2. Test 1: ReentrancyVault.sol
    target_file = PROJECT_ROOT / "Testing Sol contracts" / "ReentrancyVault.sol"
    print(f"\n--- TEST 1: {target_file.name} ---")
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

    def progress_callback(stage, message, detail):
        print(f"[{stage}] {message}: {detail}")

    print("\nRunning secure contract generation...")
    generated_secure = coordinator.generator.generate_secure_contract(
        source_code, vulnerabilities, progress_callback=progress_callback
    )

    print("\n=== FINAL GENERATED SECURE CONTRACT ===")
    print(generated_secure)
    print("=======================================")

    # Verify CEI in generated code
    withdraw_body = ""
    for name, header, body in coordinator.generator._solidity_functions(generated_secure):
        if name == "withdraw":
            withdraw_body = body

    call_pos = withdraw_body.find(".call")
    state_pos = withdraw_body.find("balances[msg.sender]")

    print(f"withdraw function body:\n{withdraw_body}")
    print(f".call pos: {call_pos}, state update pos: {state_pos}")

    if call_pos != -1 and state_pos != -1:
        if state_pos < call_pos:
            print("SUCCESS: State update occurs BEFORE external call (CEI enforced!)")
        else:
            print("FAILURE: External call occurs before state update!")
            return False

    if "require(success" not in withdraw_body and "require(sent" not in withdraw_body and "if (!success" not in withdraw_body:
        print("FAILURE: Low-level call return value was not checked!")
        return False
    else:
        print("SUCCESS: Low-level call return value is checked!")

    print("\n=== TEST 1 PASSED SUCCESSFULLY! ===")
    return True


if __name__ == "__main__":
    success = run_e2e_test()
    sys.exit(0 if success else 1)
