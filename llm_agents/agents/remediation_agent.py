"""Generate auditable candidate Solidity remediations without altering inputs."""

import difflib
import logging
import re
from pathlib import Path

from ..config import ModelConfig
from ..ollama_client import OllamaClient

logger = logging.getLogger(__name__)


class RemediationAgent:
    def __init__(self, model_config=None):
        self.model_config = model_config or ModelConfig()
        self.model_name = self.model_config.get_model("generator")
        self.client = OllamaClient(
            base_url=self.model_config.base_url,
            model=self.model_name,
            timeout=self.model_config.ollama_request_timeout,
        )

    def generate_candidate(
        self,
        source_code,
        vulnerabilities,
        contract_name,
        output_directory="remediations",
        feedback=None,
        previous_candidate=None,
    ):
        """Write a candidate patch and unified diff; the original stays untouched."""
        if not vulnerabilities:
            raise ValueError("At least one verified vulnerability is required to remediate.")
        prompt_findings = [
            {
                "type": finding.get("vulnerability_type"),
                "function": finding.get("function"),
                "functions": finding.get("affected_functions", []),
                "evidence": finding.get("evidence", ""),
                "verification": finding.get("verification_status"),
                "slither_evidence": finding.get("slither_finding"),
            }
            for finding in vulnerabilities
        ]
        prompt = (
            "Produce a complete candidate Solidity contract that fixes only the "
            "verified issues below. Preserve the contract name, pragma, imports, "
            "storage layout where practical, public/external ABI, and unrelated "
            "behavior. Use checks-effects-interactions for reentrancy, add "
            "authorization for privileged operations, and require successful "
            "low-level calls where applicable. Do not add external dependencies, "
            "invent modifiers, or claim tests passed. Return the entire Solidity "
            "source only, without Markdown fences or commentary.\n\n"
            f"Verified findings:\n{prompt_findings}\n"
        )
        required_repairs = []
        for finding in vulnerabilities:
            category = re.sub(
                r"[^a-z0-9]", "", str(finding.get("vulnerability_type", "")).lower()
            )
            if category.startswith("reentrancy"):
                required_repairs.append(
                    "REENTRANCY REQUIREMENT: In the affected function, perform all "
                    "relevant state updates before the first external call. A "
                    "success check alone or a payable cast does not fix reentrancy. "
                    "Do not leave a balance/state write after the external call."
                )
            elif category.startswith("uncheckedlowlevel"):
                required_repairs.append(
                    "UNCHECKED-CALL REQUIREMENT: Check the returned success value "
                    "and revert or handle failure explicitly."
                )
            elif category.startswith(("accesscontrol", "dangerousselfdestruct")):
                required_repairs.append(
                    "ACCESS-CONTROL REQUIREMENT: Ensure the affected privileged "
                    "operation is restricted using authorization already supported "
                    "by the contract; do not invent an owner or role."
                )
        if required_repairs:
            prompt += "\nRequired category-specific repairs:\n- "
            prompt += "\n- ".join(required_repairs) + "\n"
        if feedback:
            prompt += f"\nPrior validation feedback to address:\n{feedback}\n"
        if previous_candidate:
            prompt += (
                "\nThe following previous candidate failed validation. Correct the "
                "specific issue rather than repeating its implementation:\n"
                f"{previous_candidate}\n"
            )
        prompt += f"\nOriginal Solidity source:\n{source_code}"
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a conservative Solidity remediation engineer. "
                        "Return one complete Solidity source file only."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
        )
        candidate = self._extract_solidity(response.choices[0].message.content)
        if not candidate:
            raise ValueError("Remediation model returned no complete Solidity source.")

        output_dir = Path(output_directory)
        output_dir.mkdir(parents=True, exist_ok=True)
        safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", contract_name or "Contract")
        safe_name = Path(safe_name).stem + "_patched.sol"
        candidate_path = output_dir / safe_name
        diff_path = candidate_path.with_suffix(".diff")
        unified_diff = self._unified_diff(
            source_code,
            candidate,
            f"a/{Path(contract_name or 'Contract.sol').name}",
            f"b/{candidate_path.name}",
        )
        candidate_path.write_text(candidate, encoding="utf-8")
        diff_path.write_text(unified_diff, encoding="utf-8")
        logger.info("Saved candidate remediation to %s", candidate_path)
        return {
            "candidate_patch": candidate,
            "candidate_path": str(candidate_path),
            "diff_path": str(diff_path),
            "unified_diff": unified_diff,
        }

    @staticmethod
    def _unified_diff(original, candidate, fromfile, tofile):
        original_text = "\n".join(
            line.rstrip() for line in original.splitlines()
        ) + "\n"
        candidate_text = "\n".join(
            line.rstrip() for line in candidate.splitlines()
        ) + "\n"
        original_lines = original_text.splitlines(keepends=True)
        candidate_lines = candidate_text.splitlines(keepends=True)
        return "".join(
            difflib.unified_diff(
                original_lines,
                candidate_lines,
                fromfile=fromfile,
                tofile=tofile,
                n=0,
                lineterm="\n",
            )
        )

    @staticmethod
    def _extract_solidity(response_text):
        if not isinstance(response_text, str):
            return ""
        source = re.sub(r"^\s*```(?:solidity|sol)?\s*", "", response_text.strip(), flags=re.I)
        source = re.sub(r"\s*```\s*$", "", source)
        source = source[source.find("// SPDX"):] if "// SPDX" in source else source
        if not re.search(r"\b(?:contract|abstract\s+contract|interface|library)\s+\w+", source):
            return ""
        if re.search(r"^\s*(?:diff --git|@@\s)", source, re.M):
            return ""
        return source.rstrip() + "\n"
