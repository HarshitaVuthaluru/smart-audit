"""Focused security gates for generated secure Solidity contracts."""

import unittest
from pathlib import Path

from llm_agents.agents.generator import GeneratorAgent


class SecureGeneratorValidationTests(unittest.TestCase):
    REENTRANCY = [{"vulnerability_type": "REENTRANCY"}]
    SAMPLE_DIR = Path(__file__).resolve().parents[1] / "Testing Sol contracts"

    def test_accepts_checked_cei_low_level_call(self):
        source = """pragma solidity ^0.8.20;
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "balance");
        balances[msg.sender] -= amount;
        (bool success,) = payable(msg.sender).call{value: amount}("");
        require(success, "transfer failed");
    }
}"""

        self.assertEqual(
            GeneratorAgent._security_validation_failures(source, self.REENTRANCY), []
        )

    def test_rejects_external_call_before_effect(self):
        source = """pragma solidity ^0.8.20;
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "balance");
        (bool success,) = payable(msg.sender).call{value: amount}("");
        require(success, "transfer failed");
        balances[msg.sender] -= amount;
    }
}"""

        failures = GeneratorAgent._security_validation_failures(source, self.REENTRANCY)

        self.assertTrue(any("CEI violation" in failure for failure in failures))

    def test_warns_for_existing_weak_randomness_but_rejects_tx_origin(self):
        source = """pragma solidity ^0.8.20;
contract Lottery {
    function pick() external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender)));
    }
}"""

        report = GeneratorAgent._security_validation_report(
            source, [{"vulnerability_type": "WEAK_RANDOMNESS"}]
        )

        self.assertTrue(any("weak" in warning for warning in report["warnings"]))
        origin_report = GeneratorAgent._security_validation_report(
            "pragma solidity ^0.8.20; contract X { function f() external { require(tx.origin == msg.sender); } }", []
        )
        self.assertTrue(any("tx.origin" in failure for failure in origin_report["blocking"]))

    def test_random_helper_never_requires_owner_authorization(self):
        source = (self.SAMPLE_DIR / "Lottery.sol").read_text(encoding="utf-8")

        report = GeneratorAgent._security_validation_report(
            source, [{"vulnerability_type": "ACCESS_CONTROL", "affected_functions": ["random()"]}]
        )

        self.assertFalse(any("authorization" in failure for failure in report["blocking"]))

    def test_vulnerable_bank_user_withdrawal_is_recognized_as_account_owned(self):
        source = (self.SAMPLE_DIR / "VulnerableBank.sol").read_text(encoding="utf-8")
        withdraw = next(
            entry for entry in GeneratorAgent._solidity_functions(source) if entry[0] == "withdraw"
        )

        is_user_withdrawal, explanation = GeneratorAgent._is_user_withdrawal(
            withdraw[0], withdraw[2]
        )

        self.assertTrue(is_user_withdrawal)
        self.assertIn("caller's own recorded balance", explanation)

    def test_emergency_withdraw_requires_owner_authorization(self):
        vulnerable = (self.SAMPLE_DIR / "VulnerableBank.sol").read_text(encoding="utf-8")
        source = """pragma solidity ^0.8.20;
contract Treasury {
    address owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function emergencyWithdraw() external onlyOwner {
        payable(msg.sender).transfer(address(this).balance);
    }
}"""

        report = GeneratorAgent._security_validation_report(
            source, [{"vulnerability_type": "ACCESS_CONTROL"}], source
        )
        vulnerable_report = GeneratorAgent._security_validation_report(
            vulnerable, [{"vulnerability_type": "ACCESS_CONTROL"}], vulnerable
        )

        self.assertFalse(any("emergencyWithdraw" in failure for failure in report["blocking"]))
        self.assertTrue(any("emergencyWithdraw" in failure for failure in vulnerable_report["blocking"]))

    def test_reentrancy_vault_fix_is_accepted_after_effects_precede_call(self):
        original = (self.SAMPLE_DIR / "ReentrancyVault.sol").read_text(encoding="utf-8")
        repaired = original.replace(
            """        (bool success,) = msg.sender.call{value: amount}(\"\");
        require(success);

        balances[msg.sender] -= amount;""",
            """        balances[msg.sender] -= amount;

        (bool success,) = msg.sender.call{value: amount}(\"\");
        require(success);""",
        )

        report = GeneratorAgent._security_validation_report(repaired, self.REENTRANCY, original)

        self.assertFalse(any("CEI violation" in failure for failure in report["blocking"]))

    def test_unrestricted_and_owner_protected_selfdestruct(self):
        original = (self.SAMPLE_DIR / "OwnershipBug.sol").read_text(encoding="utf-8")
        protected = """pragma solidity ^0.8.20;
contract OwnershipBug {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function destroy() external onlyOwner { selfdestruct(payable(msg.sender)); }
}"""

        protected_report = GeneratorAgent._security_validation_report(
            protected, [{"vulnerability_type": "DANGEROUS_SELFDESTRUCT"}], original
        )
        unprotected_report = GeneratorAgent._security_validation_report(
            original, [{"vulnerability_type": "DANGEROUS_SELFDESTRUCT"}], original
        )

        self.assertFalse(any("destruction" in failure for failure in protected_report["blocking"]))
        self.assertTrue(any("unrestricted contract destruction" in failure for failure in unprotected_report["blocking"]))
