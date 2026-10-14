"""Unit tests for multi-attempt secure generation repair loop, compiler feedback, and Skeptic reasoning grounding."""

import unittest
from unittest.mock import MagicMock
from pathlib import Path

from llm_agents.config import ModelConfig
from llm_agents.agents.generator import GeneratorAgent
from llm_agents.agents.skeptic import SkepticAgent


class SecureGenerationRepairLoopTests(unittest.TestCase):
    SAMPLE_DIR = Path(__file__).resolve().parents[1] / "Testing Sol contracts"
    REENTRANCY = [{"vulnerability_type": "REENTRANCY", "affected_functions": ["withdraw(uint256)"]}]

    def test_multi_attempt_repair_loop_retries_and_succeeds(self):
        config = ModelConfig(secure_generation_attempts=3)
        agent = GeneratorAgent(model_config=config)

        original_source = (self.SAMPLE_DIR / "ReentrancyVault.sol").read_text(encoding="utf-8")

        vulnerable_draft = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ReentrancyVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        (bool success,) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }

    receive() external payable {}
}"""

        repaired_draft = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ReentrancyVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    receive() external payable {}
}"""

        agent._chat = MagicMock(side_effect=[vulnerable_draft, repaired_draft])
        progress_events = []

        def progress_cb(stage, message, detail):
            progress_events.append((stage, message))

        result = agent.generate_secure_contract(original_source, self.REENTRANCY, progress_callback=progress_cb)

        self.assertIn("balances[msg.sender] -= amount;", result.split("msg.sender.call")[0])
        self.assertIn("require(success", result)
        self.assertEqual(agent._chat.call_count, 2)
        second_prompt = agent._chat.call_args_list[1][0][0]
        self.assertIn("REPAIR ATTEMPT 1 OF 2", second_prompt)
        self.assertIn("CEI violation", second_prompt)

    def test_repair_fails_safely_when_max_attempts_exhausted(self):
        config = ModelConfig(secure_generation_attempts=3)
        agent = GeneratorAgent(model_config=config)

        original_source = (self.SAMPLE_DIR / "ReentrancyVault.sol").read_text(encoding="utf-8")

        vulnerable_draft = original_source  # retains CEI violation and low level call issues

        agent._chat = MagicMock(return_value=vulnerable_draft)

        with self.assertRaises(ValueError) as ctx:
            agent.generate_secure_contract(original_source, self.REENTRANCY)

        self.assertIn("failed security validation after 3 repair attempts", str(ctx.exception))
        self.assertEqual(agent._chat.call_count, 3)

    def test_rejects_hallucinated_functions(self):
        original = (self.SAMPLE_DIR / "ReentrancyVault.sol").read_text(encoding="utf-8")
        hallucinated = original + """

    function migrateTo(address newOwner) external {}
"""

        report = GeneratorAgent._generation_quality_report(original, hallucinated)
        self.assertTrue(any("unauthorized function signature" in failure for failure in report["blocking"]))

    def test_skeptic_grounding_corrects_contradictory_reasoning(self):
        finding = {"vulnerability_type": "REENTRANCY", "code_snippet": "msg.sender.call{value: amount}(''); balances[msg.sender] -= amount;"}
        contradictory_reasoning = "The contract correctly follows checks-effects-interactions and the state change occurs before the external call."
        contract_source = "function withdraw() external { (bool success,) = msg.sender.call{value: amount}(''); balances[msg.sender] -= amount; }"

        grounded = SkepticAgent._ground_execution_order(finding, contradictory_reasoning, contract_source)

        self.assertIn("Source execution order shows an external value call before the state update", grounded)
        self.assertIn("contradicted the supplied Solidity snippet", grounded)


if __name__ == "__main__":
    unittest.main()
