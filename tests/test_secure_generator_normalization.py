"""Mechanical compilation normalization checks for secure contract output."""

from pathlib import Path
import unittest

from llm_agents.agents.generator import GeneratorAgent


class SecureGeneratorNormalizationTests(unittest.TestCase):
    SAMPLE_DIR = Path(__file__).resolve().parents[1] / "Testing Sol contracts"

    def test_solidity_08_samples_drop_orphaned_safemath_using(self):
        for filename in (
            "ReentrancyVault.sol", "Lottery.sol", "OwnershipBug.sol", "VulnerableBank.sol",
        ):
            with self.subTest(filename=filename):
                source = (self.SAMPLE_DIR / filename).read_text(encoding="utf-8")
                normalized = GeneratorAgent._normalize_generated_solidity(
                    source + "\nusing SafeMath for uint256;\nusing SafeMath for uint;\n"
                )

                self.assertNotIn("using SafeMath", normalized)
                self.assertIn("pragma solidity ^0.8.20;", normalized)

    def test_preserves_safemath_when_a_library_is_defined(self):
        source = """pragma solidity ^0.8.20;
library SafeMath { function add(uint256 a, uint256 b) internal pure returns (uint256) { return a + b; } }
contract Mixed { using SafeMath for uint256; }
"""

        normalized = GeneratorAgent._normalize_generated_solidity(source)

        self.assertIn("using SafeMath for uint256;", normalized)

    def test_removes_inline_orphaned_safemath_using(self):
        source = "pragma solidity ^0.8.20; using SafeMath for uint256; contract Mixed {}"

        normalized = GeneratorAgent._normalize_generated_solidity(source)

        self.assertNotIn("using SafeMath", normalized)

    def test_removes_duplicate_contract_definition(self):
        source = """pragma solidity ^0.8.20;
contract Mixed { function first() external {} }
contract Mixed { function duplicate() external {} }
"""

        normalized = GeneratorAgent._normalize_generated_solidity(source)

        self.assertEqual(normalized.count("contract Mixed"), 1)
        self.assertNotIn("duplicate", normalized)

    def test_removes_duplicate_directives_imports_and_markdown(self):
        source = """```solidity
// SPDX-License-Identifier: MIT
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
pragma solidity ^0.8.20;
import "./A.sol";
import "./A.sol";
contract Mixed {}
```
"""

        normalized = GeneratorAgent._normalize_generated_solidity(source)

        self.assertEqual(normalized.count("SPDX-License-Identifier"), 1)
        self.assertEqual(normalized.count("pragma solidity"), 1)
        self.assertEqual(normalized.count('import "./A.sol";'), 1)
        self.assertNotIn("```", normalized)
