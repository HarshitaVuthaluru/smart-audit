"""Post-patch comparison of Slither findings for secure-contract generation."""

import unittest

from static_analysis.security_validation import compare_detector_findings


def slither_finding(check, impact, signature, description):
    return {
        "check": check,
        "impact": impact,
        "confidence": "High",
        "description": description,
        "elements": [{
            "type": "function",
            "name": f"Vault.{signature}",
            "type_specific_fields": {"signature": signature},
        }],
    }


class SecureReverificationTests(unittest.TestCase):
    def test_accepts_resolved_target_and_reports_before_after_findings(self):
        original = [[
            slither_finding(
                "reentrancy-eth",
                "High",
                "withdraw(uint256)",
                "Reentrancy in Vault.withdraw(uint256)",
            ),
            slither_finding(
                "naming-convention",
                "Low",
                "deposit()",
                "Function name should use mixedCase",
            ),
        ]]
        generated = [[
            slither_finding(
                "naming-convention",
                "Low",
                "deposit()",
                "Function name should use mixedCase",
            ),
        ]]

        result = compare_detector_findings(
            original,
            generated,
            [{"vulnerability_type": "REENTRANCY"}],
        )

        self.assertTrue(result["passed"])
        self.assertEqual(result["original_finding_count"], 2)
        self.assertEqual(result["generated_finding_count"], 1)
        self.assertEqual(result["resolved_findings"][0]["check"], "reentrancy-eth")
        self.assertEqual(result["remaining_target_findings"], [])
        self.assertEqual(result["introduced_findings"], [])

    def test_rejects_target_finding_that_remains(self):
        finding = slither_finding(
            "unchecked-lowlevel",
            "High",
            "sendEther(address,uint256)",
            "Unchecked low-level call in Vault.sendEther(address,uint256)",
        )

        result = compare_detector_findings(
            [[finding]],
            [[finding]],
            [{"vulnerability_type": "unchecked_low_level_calls"}],
        )

        self.assertFalse(result["passed"])
        self.assertEqual(result["remaining_target_findings"][0]["check"], "unchecked-lowlevel")

    def test_rejects_new_high_severity_finding(self):
        introduced = slither_finding(
            "suicidal",
            "High",
            "destroy()",
            "Unprotected contract destruction",
        )

        result = compare_detector_findings([], [[introduced]], [])

        self.assertFalse(result["passed"])
        self.assertEqual(result["blocking_findings"][0]["check"], "suicidal")

    def test_rejects_finding_escalated_to_high_severity(self):
        original = slither_finding(
            "arbitrary-send-eth",
            "Medium",
            "withdraw()",
            "Withdraw sends ether to a user-controlled address",
        )
        generated = slither_finding(
            "arbitrary-send-eth",
            "High",
            "withdraw()",
            "Withdraw sends ether to a user-controlled address",
        )

        result = compare_detector_findings([[original]], [[generated]], [])

        self.assertFalse(result["passed"])
        self.assertEqual(result["blocking_findings"][0]["impact"], "High")

    def test_reports_but_does_not_block_new_low_severity_finding(self):
        introduced = slither_finding(
            "naming-convention",
            "Low",
            "withdraw()",
            "Function name should use mixedCase",
        )

        result = compare_detector_findings([], [[introduced]], [])

        self.assertTrue(result["passed"])
        self.assertEqual(result["introduced_findings"][0]["check"], "naming-convention")


if __name__ == "__main__":
    unittest.main()
