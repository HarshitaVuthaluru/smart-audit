import unittest

from llm_agents.agents.remediation_agent import RemediationAgent
from llm_agents.agents.verification_agent import VerificationAgent
from llm_agents.agents.analyzer import AnalyzerAgent
from static_analysis.slither_detectors import DETECTORS
from static_analysis.security_validation import compare_detector_findings
from eth_utils import keccak


def slither_finding(check, signature, description, lines):
    return {
        "check": check,
        "impact": "High",
        "confidence": "High",
        "description": description,
        "elements": [{
            "type": "function",
            "name": f"Vault.{signature}",
            "type_specific_fields": {"signature": signature},
            "source_mapping": {"lines": lines},
        }],
    }


class SmartAuditVerificationTests(unittest.TestCase):
    def test_detector_registry_loads_concrete_classes(self):
        self.assertTrue(DETECTORS)
        self.assertTrue(all(isinstance(detector.__name__, str) for detector in DETECTORS))

    def test_confirmed_reentrancy_has_component_breakdown(self):
        candidate = {
            "vulnerability_type": "reentrancy",
            "function": "withdraw(uint256)",
            "affected_functions": ["withdraw(uint256)"],
            "source_location": {"start_line": 10, "end_line": 18},
            "explanation": "External call before balances state update enables reentrancy.",
            "evidence": "balances[msg.sender] is updated after the external call.",
        }
        finding = slither_finding(
            "reentrancy-eth",
            "withdraw(uint256)",
            "Reentrancy in Vault.withdraw(uint256): external call before state update",
            list(range(10, 19)),
        )

        result = VerificationAgent().verify([candidate], [[finding]])
        verified = result["verified_vulnerabilities"][0]

        self.assertEqual(verified["verification_status"], "Confirmed")
        self.assertEqual(verified["category_agreement"], 1.0)
        self.assertEqual(verified["location_agreement"], 1.0)
        self.assertGreaterEqual(verified["verification_score"], 0.70)
        self.assertEqual(verified["slither_finding"]["check"], "reentrancy-eth")

    def test_access_control_match_without_full_location_support_is_partial(self):
        candidate = {
            "vulnerability_type": "access_control",
            "function": "destroy()",
            "affected_functions": ["destroy()"],
            "source_location": {"start_line": 20, "end_line": 24},
            "explanation": "Unprotected destroy function permits unauthorized selfdestruct.",
            "evidence": "The destroy function has no authorization guard.",
        }
        finding = slither_finding(
            "suicidal",
            "destroy()",
            "Unprotected contract destruction in Vault.destroy()",
            [3, 4],
        )

        verified = VerificationAgent().verify([candidate], [[finding]])[
            "verified_vulnerabilities"
        ][0]

        self.assertEqual(verified["verification_status"], "Partially Supported")
        self.assertEqual(verified["category_agreement"], 1.0)
        self.assertEqual(verified["location_agreement"], 0.8)

    def test_missing_slither_evidence_is_unconfirmed(self):
        result = VerificationAgent().verify(
            [{
                "vulnerability_type": "bad_randomness",
                "function": "draw()",
                "explanation": "Predictable block timestamp randomness.",
            }],
            [],
        )

        verified = result["verified_vulnerabilities"][0]
        self.assertEqual(verified["verification_status"], "Unconfirmed")
        self.assertEqual(verified["verification_score"], 0.0)
        self.assertIsNone(verified["slither_finding"])

    def test_remediation_parser_accepts_complete_contract_only(self):
        source = "```solidity\npragma solidity ^0.8.20;\ncontract Vault {}\n```"
        self.assertIn("contract Vault", RemediationAgent._extract_solidity(source))
        self.assertEqual(
            RemediationAgent._extract_solidity("Here is a patch: balances = 0;"),
            "",
        )
        diff = RemediationAgent._unified_diff(
            "contract Vault {}", "contract Vault { }\n", "a/Vault.sol", "b/Vault.sol"
        )
        self.assertIn("--- a/Vault.sol\n", diff)
        self.assertNotIn("-}+}", diff)

    def test_targeted_analysis_uses_high_risk_function_source(self):
        agent = object.__new__(AnalyzerAgent)
        agent._call_llm = lambda _system, _prompt: (
            '{"vulnerabilities":[{"vulnerability_type":"reentrancy",'
            '"confidence_score":0.9,"reasoning":"Call before balance update.",'
            '"affected_functions":["withdraw(uint256)"],"impact":"High"}]}'
        )
        contract_info = {
            "source_code": "contract Vault {}",
            "function_details": [{
                "contract": "Vault",
                "function": "withdraw",
                "function_id": "withdraw(uint256)",
                "visibility": "external",
                "start_line": 4,
                "end_line": 8,
                "content": (
                    "function withdraw(uint256 amount) external { "
                    "(bool ok,) = msg.sender.call{value: amount}(\"\"); "
                    "balances[msg.sender] -= amount; }"
                ),
            }],
        }

        findings = agent._run_targeted_analysis(contract_info, [])

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["detection_pass"], "targeted")
        self.assertEqual(findings[0]["affected_functions"], ["withdraw(uint256)"])

    def test_targeted_function_hash_resolves_to_exact_signature(self):
        signature = "withdraw(uint256)"
        truncated_hash = "0x" + keccak(text=signature).hex()[:40]

        resolved = AnalyzerAgent._normalize_function_reference_for_lookup(
            truncated_hash, {signature}
        )

        self.assertEqual(resolved, signature)

    def test_reverification_ignores_scratch_path_in_detector_identity(self):
        original = [{
            "check": "solc-version",
            "impact": "Informational",
            "confidence": "High",
            "description": (
                "Version constraint ^0.8.20 contains known issues. "
                "It is used by ^0.8.20 (Testing Sol contracts/ReentrancyVault.sol#2)"
            ),
            "elements": [],
        }]
        patched = [{
            **original[0],
            "description": (
                "Version constraint ^0.8.20 contains known issues. "
                "It is used by ^0.8.20 "
                "(Testing Sol contracts/.smartaudit_candidate_abcd.sol#2)"
            ),
        }]

        result = compare_detector_findings(original, patched, [])

        self.assertEqual(result["introduced_findings"], [])
        self.assertTrue(result["passed"])


if __name__ == "__main__":
    unittest.main()
