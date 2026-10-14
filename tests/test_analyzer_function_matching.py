"""Regression tests for Analyzer LLM function-reference matching."""

import unittest
from pathlib import Path

from llm_agents.agents.analyzer import AnalyzerAgent


class AnalyzerFunctionMatchingTests(unittest.TestCase):
    @staticmethod
    def _deterministic_types(filename: str) -> set[str]:
        source = (Path(__file__).resolve().parent.parent / "Testing Sol contracts" / filename).read_text(encoding="utf-8")
        findings = AnalyzerAgent._add_deterministic_findings([], {"source_code": source, "function_details": []})
        return {finding["vulnerability_type"] for finding in findings}

    def test_ownership_bug_never_returns_an_empty_vulnerability_list(self):
        findings = self._deterministic_types("OwnershipBug.sol")

        self.assertTrue(findings, "OwnershipBug must not produce an empty vulnerability list")
        self.assertIn("access_control", findings)
        self.assertIn("dangerous_selfdestruct", findings)

    def test_analyzer_regression_contracts_keep_direct_source_findings(self):
        expected = {
            "ReentrancyVault.sol": "reentrancy",
            "Lottery.sol": "timestamp_dependence",
            "VulnerableBank.sol": "access_control",
            "Mixed.sol": "dangerous_selfdestruct",
        }
        for filename, vulnerability_type in expected.items():
            with self.subTest(filename=filename):
                self.assertIn(vulnerability_type, self._deterministic_types(filename))

    def test_user_owned_balance_operation_is_not_privileged_access_control(self):
        source = """contract Wallet {
            mapping(address => uint256) balances;
            function withdraw(uint256 amount) external {
                require(balances[msg.sender] >= amount);
                balances[msg.sender] -= amount;
            }
        }"""
        findings = AnalyzerAgent._add_deterministic_findings([], {"source_code": source, "function_details": []})

        self.assertNotIn("access_control", {finding["vulnerability_type"] for finding in findings})

    def test_normalizes_llm_function_references_for_lookup(self):
        cases = [
        ("withdraw", "withdraw(uint256)"),
        ("withdraw()", "withdraw(uint256)"),
        ("withdraw(uint256)", "withdraw(uint256)"),
        ("Contract.withdraw", "withdraw(uint256)"),
        ("Contract.withdraw()", "withdraw(uint256)"),
        ("Contract.withdraw(uint256)", "withdraw(uint256)"),
        ("withdraw(uint256)_0x6d9485e7", "withdraw(uint256)"),
        ("withdraw_0x1234abcd", "withdraw(uint256)"),
        ("withdraw(uint256)_42", "withdraw(uint256)"),
        ("withdraw(uint256)_compiler_7", "withdraw(uint256)"),
        ("Contract.withdraw(uint256)_deadbeef", "withdraw(uint256)"),
        ]
        for reference, expected in cases:
            with self.subTest(reference=reference):
                self.assertEqual(
                    AnalyzerAgent._normalize_function_reference_for_lookup(
                        reference, {"withdraw(uint256)"}
                    ),
                    expected,
                )

    def test_does_not_resolve_ambiguous_overloaded_bare_name(self):
        allowed = {"withdraw()", "withdraw(uint256)"}

        self.assertIsNone(AnalyzerAgent._normalize_function_reference_for_lookup("withdraw", allowed))
        self.assertIsNone(AnalyzerAgent._normalize_function_reference_for_lookup("withdraw_0x1234abcd", allowed))

    def test_validation_keeps_original_llm_function_name_when_normalized_lookup_exists(self):
        original_name = "withdraw(uint256)_0x6d9485e7"
        findings = [{"vulnerability_type": "reentrancy", "affected_functions": [original_name]}]
        contract_info = {
            "function_details": [{"function": "withdraw", "function_id": "withdraw(uint256)"}]
        }

        validated = AnalyzerAgent._validate_findings(findings, contract_info)

        self.assertEqual(validated[0]["affected_functions"], ["withdraw(uint256)"])

    def test_normalizes_abi_selector_to_a_known_function(self):
        self.assertEqual(
            AnalyzerAgent._normalize_function_reference_for_lookup(
                "0x2e1a7d4d", {"withdraw(uint256)"}
            ),
            "withdraw(uint256)",
        )

    def test_validation_keeps_unmappable_identifier(self):
        findings = [{"vulnerability_type": "reentrancy", "affected_functions": ["0x07f7ecb66d788ab01dc93b9b71a88401de7d0f2e"]}]
        contract_info = {"function_details": [{"function": "withdraw", "function_id": "withdraw(uint256)"}]}

        validated = AnalyzerAgent._validate_findings(findings, contract_info)

        self.assertEqual(len(validated), 1)
        self.assertEqual(validated[0]["affected_functions"], ["0x07f7ecb66d788ab01dc93b9b71a88401de7d0f2e"])

    def test_maps_file_line_and_byte_offset_to_enclosing_function(self):
        source = """contract OwnershipBug {
    address owner;
    function setOwner(address next) external {
        owner = next;
    }
    function helper() internal {}
}
"""
        details = [
            {"contract": "OwnershipBug", "function": "setOwner", "function_id": "setOwner(address)", "start_line": 3, "end_line": 5},
            {"contract": "OwnershipBug", "function": "helper", "function_id": "helper()", "start_line": 6, "end_line": 6},
        ]
        allowed = {detail["function_id"] for detail in details}

        self.assertEqual(
            AnalyzerAgent._normalize_function_reference_for_lookup("OwnershipBug.sol#4", allowed, details, source),
            "setOwner(address)",
        )
        self.assertEqual(
            AnalyzerAgent._normalize_function_reference_for_lookup("OwnershipBug.sol#byte:100", allowed, details, source),
            "setOwner(address)",
        )

    def test_maps_special_overloaded_and_inherited_function_references(self):
        details = [
            {"contract": "Base", "function": "withdraw", "function_id": "withdraw(uint256)", "start_line": 1, "end_line": 2},
            {"contract": "Derived", "function": "withdraw", "function_id": "withdraw(address)", "start_line": 4, "end_line": 5},
            {"contract": "Derived", "function": "constructor", "function_id": "constructor(address)", "start_line": 6, "end_line": 6},
            {"contract": "Derived", "function": "fallback", "function_id": "fallback()", "start_line": 7, "end_line": 7},
            {"contract": "Derived", "function": "receive", "function_id": "receive()", "start_line": 8, "end_line": 8},
        ]
        allowed = {detail["function_id"] for detail in details}

        self.assertEqual(
            AnalyzerAgent._normalize_function_reference_for_lookup("Base.withdraw(uint256)", allowed, details),
            "withdraw(uint256)",
        )
        self.assertIsNone(AnalyzerAgent._normalize_function_reference_for_lookup("withdraw", allowed, details))
        self.assertEqual(AnalyzerAgent._normalize_function_reference_for_lookup("constructor(address)", allowed, details), "constructor(address)")
        self.assertEqual(AnalyzerAgent._normalize_function_reference_for_lookup("fallback()", allowed, details), "fallback()")
        self.assertEqual(AnalyzerAgent._normalize_function_reference_for_lookup("receive()", allowed, details), "receive()")

    def test_attaches_snippet_for_function_with_generated_suffix(self):
        original_name = "withdraw(uint256)_0x6d9485e7"
        findings = [{"vulnerability_type": "reentrancy", "affected_functions": [original_name]}]
        contract_info = {
            "function_details": [{
                "contract": "Contract",
                "function": "withdraw",
                "function_id": "withdraw(uint256)",
                "content": "function withdraw(uint256 amount) external { /* vulnerable */ }",
            }]
        }

        AnalyzerAgent._attach_code_snippets(AnalyzerAgent, findings, contract_info)

        self.assertEqual(findings[0]["affected_functions"], [original_name])
        self.assertEqual(
            findings[0]["code_snippet"],
            "function withdraw(uint256 amount) external { /* vulnerable */ }",
        )
