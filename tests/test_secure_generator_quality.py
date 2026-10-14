"""Identity and signature quality checks for secure-contract generation."""

import unittest

from llm_agents.agents.generator import GeneratorAgent


class SecureGeneratorQualityTests(unittest.TestCase):
    def test_equivalent_types_preserve_function_identity(self):
        original = """pragma solidity ^0.8.20;
contract Vault is Base {
    event Withdraw(address indexed user, uint amount);
    uint public total;
    modifier active() { _; }
    function withdraw(unsigned amount, address payable recipient) external active {}
}"""
        generated = """pragma solidity ^0.8.20;
contract Vault is Base {
    event Withdraw(address indexed user, uint256 amount);
    uint256 public total;
    modifier active() { _; }
    function withdraw(uint256 amount, address payable recipient) external active {}
}"""

        report = GeneratorAgent._generation_quality_report(original, generated)

        self.assertEqual(report["blocking"], [])

    def test_rejects_removed_contract_event_or_modifier_usage(self):
        original = """pragma solidity ^0.8.20;
contract Vault { event Withdraw(address user); modifier active() { _; } function withdraw(uint amount) external active {} }"""
        generated = """pragma solidity ^0.8.20;
contract Renamed { function withdraw(uint256 amount) external {} }"""

        report = GeneratorAgent._generation_quality_report(original, generated)

        self.assertTrue(any("contract name Vault" in item for item in report["blocking"]))
        self.assertTrue(any("event" in item for item in report["blocking"]))

