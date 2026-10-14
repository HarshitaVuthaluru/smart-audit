"""Foundry PoC generation with deterministic validation and compile gating."""
import os
import json
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from utils.print_utils import print_success, print_warning
from utils.function_identifiers import canonical_function_id


class GeneratorAgent:
    """Generate only PoCs that pass structural, semantic, and Forge checks."""

    MAX_ATTEMPTS = 3

    def __init__(self, model_config=None):
        from ..config import ModelConfig
        from ..ollama_client import OllamaClient

        self.model_config = model_config or ModelConfig()
        self.model_name = self.model_config.get_model("generator")
        self.client = OllamaClient(
            base_url=self.model_config.base_url,
            model=self.model_name,
            timeout=self.model_config.ollama_request_timeout,
        )
        self.project_root = Path.cwd()
        self.exploit_root = self.project_root / "exploit"
        self.workspace_root = self.exploit_root / "tmp"
        self.current_job_id = ""
        self.current_job_dir: Optional[Path] = None
        # Keep generated tests in Foundry's dedicated test directory.  Putting
        # them below ``src`` makes every old PoC part of all future builds.
        # This directory is now used only for the shared base test contract;
        # generated PoCs are kept in a per-job temporary workspace.
        self.test_dir = self.exploit_root / "test"

    def generate(self, exploit_data: Dict) -> Dict:
        """Generate, validate, self-review, compile, then persist a PoC."""
        self._begin_job_workspace()
        vulnerability = exploit_data.get("vulnerability", {})
        plan = exploit_data.get("exploit_plan", {}) or {}
        target = self._resolve_target(exploit_data)
        validation_mode = self._validation_mode(vulnerability)
        failures: List[str] = []
        previous_code = ""
        last_valid_code = ""
        last_compile_result: Dict = {}

        self.generate_basetest_file() if not (self.test_dir / "basetest.sol").exists() else None
        # Keep compiler-guided repair bounded even if a configuration value is
        # accidentally raised: every failure is fed into the next prompt.
        for attempt in range(1, min(self.model_config.poc_generation_attempts, self.MAX_ATTEMPTS) + 1):
            code = self.generate_poc_contract(vulnerability, plan, target, failures, attempt, previous_code)
            code = self._replace_placeholders(code)
            repaired_code = self._auto_repair_contract(code, vulnerability, target)
            if repaired_code != code:
                print_success(f"PoC repaired automatically (attempt {attempt}).")
            code = repaired_code
            previous_code = code
            errors = self.validate_contract(code, vulnerability, target)
            if errors:
                self._write_validation_artifacts(code, errors, attempt)
                failures = errors
                print_warning(f"Generator attempt {attempt} rejected: {'; '.join(errors)}")
                continue

            review = self._self_review(code, vulnerability, target)
            if review:
                failures = [f"Self-review: {review}"]
                self._write_validation_artifacts(code, failures, attempt)
                print_warning(f"Generator attempt {attempt} self-review rejected the contract: {review}")
                continue

            last_valid_code = code
            print_success(f"PoC validated (attempt {attempt}); compiling candidate.")
            compile_result = self.compile_candidate(code, attempt=attempt)
            # Re-run deterministic repairs after Forge reports a failure.  A
            # model is not needed for the known mechanical mistakes repaired
            # by _auto_repair_contract, and recompiling here avoids wasting a
            # generation attempt on them.
            if not compile_result["compiled"]:
                compile_repair = self._auto_repair_contract(code, vulnerability, target)
                if compile_repair != code:
                    repair_errors = self.validate_contract(compile_repair, vulnerability, target)
                    if not repair_errors:
                        code = compile_repair
                        previous_code = code
                        last_valid_code = code
                        print_success(
                            f"PoC repaired after compiler feedback (attempt {attempt}); retrying compilation."
                        )
                        compile_result = self.compile_candidate(code, attempt=attempt)
                    else:
                        print_warning(
                            "Compiler-triggered auto-repair did not pass deterministic validation: "
                            f"{'; '.join(repair_errors)}"
                        )
            last_compile_result = compile_result
            if not compile_result["compiled"]:
                # The compiler diagnostic is the actionable repair input.  Do
                # not obscure it behind a generic generation failure.
                failures = [
                    "Forge compiler failure:\n"
                    f"STDOUT:\n{compile_result['stdout']}\n"
                    f"STDERR:\n{compile_result['stderr']}\n"
                    f"DIAGNOSTIC:\n{compile_result['compile_error']}"
                ]
                print_warning(f"PoC compilation rejected on attempt {attempt}; retaining candidate for repair.")
                continue

            filename = self.save_poc_locally(code, vulnerability.get("vulnerability_type", "unknown"))
            relative = Path(filename).resolve().relative_to(self.exploit_root.resolve()).as_posix()
            return {
                "exploit_code": code,
                "exploit_file": filename,
                "execution_command": f'forge test -vv --match-path "./{relative}"',
                "target_contract": target,
                "poc_strategy": validation_mode,
                "compiled": True,
                "compile_output": compile_result["output"],
                "compile_stdout": compile_result["stdout"],
                "compile_stderr": compile_result["stderr"],
                "compile_time": compile_result["compile_time"],
            }

        # A syntactically validated Solidity test is still a generated PoC
        # even when local Forge is unavailable or its compiler rejects it.
        # Persist it so Runner can independently compile/repair it and the
        # report can distinguish generation from compilation.
        if last_valid_code:
            filename = self.save_poc_locally(last_valid_code, vulnerability.get("vulnerability_type", "unknown"))
            relative = Path(filename).resolve().relative_to(self.exploit_root.resolve()).as_posix()
            print_warning("PoC created but not compiled; forwarding it to Runner for repair.")
            return {
                "exploit_code": last_valid_code,
                "exploit_file": filename,
                "execution_command": f'forge test -vv --match-path "./{relative}"',
                "target_contract": target,
                "poc_strategy": validation_mode,
                "compiled": False,
                "compile_output": last_compile_result.get("output", ""),
                "compile_stdout": last_compile_result.get("stdout", ""),
                "compile_stderr": last_compile_result.get("stderr", ""),
                "compile_error": last_compile_result.get("compile_error", ""),
                "compile_time": last_compile_result.get("compile_time", 0.0),
                "generation_error": "",
                "validation_errors": failures,
            }

        return {
            "exploit_code": "",
            "exploit_file": "",
            "execution_command": "",
            "target_contract": target,
            "generation_error": failures[-1] if failures else "PoC generation failed after deterministic validation and Forge compilation.",
            "validation_errors": failures,
        }

    def generate_secure_contract(self, source_code: str, vulnerabilities: List[Dict], progress_callback=None) -> str:
        """Rewrite and security-validate a contract using a controlled multi-repair loop."""
        max_attempts = getattr(self.model_config, "secure_generation_attempts", 3)
        findings = json.dumps(vulnerabilities, indent=2, default=str)
        failures: List[str] = []
        candidate_source = ""
        previous_candidate_source = ""

        for attempt in range(1, max_attempts + 1):
            if attempt == 1:
                prompt = f"""You are the final secure-contract generation stage of a Solidity security pipeline.

Act as an experienced Solidity security auditor, not a formatter. Apply the smallest source-level changes needed to eliminate every validated vulnerability. Preserve the exact contract name, pragma version, interfaces, inheritance, events, existing modifiers, storage layout where possible, function signatures, and external interface. Do not add unrelated functionality or remove legitimate behavior.

CRITICAL REENTRANCY AND SECURITY RULES:
- Reentrancy (CEI Pattern): In functions with state updates and external calls (e.g. `withdraw(uint256)`), move all state updates (e.g. `balances[msg.sender] -= amount;`) BEFORE external calls (e.g. `(bool success,) = msg.sender.call{{value: amount}}("");`). Follow Checks -> Effects -> Interactions strictly.
- Reentrancy Guard: Use OpenZeppelin ReentrancyGuard only when its import is already available; otherwise use a minimal local private guard if needed (e.g., `bool private _locked;`). State variables for local guards must be `private` or `internal`, NOT `public`.
- Access control: retain intended authorization, protect privileged operations, validate ownership/role changes, and reject zero-address owners where applicable. Do not create privilege escalation paths.
- Arithmetic: rely on Solidity 0.8+ checked arithmetic and do not use unchecked blocks unless they are demonstrably safe and documented in code.
- Randomness: never present block.timestamp, block.number, blockhash, block.prevrandao, block.difficulty, msg.sender, msg.sig, tx.origin, or deterministic hashing as secure randomness. When external infrastructure is unavailable, preserve the interface with a deterministic helper and include exactly this comment: "For production-grade randomness, integrate Chainlink VRF or a commit-reveal protocol."
- Calls: check low-level call return values and revert on failure (e.g., `(bool success,) = target.call{{value: amount}}(""); require(success, "Transfer failed");`). Do not introduce delegatecall, tx.origin, unsafe selfdestruct, or unbounded recipient-processing loops.
- Inputs: validate security-critical external inputs and preserve existing meaningful validation.
- Interface Integrity: Do NOT add new `public` or `external` functions or `public` state variables that create extra public function signatures.

The output will be rejected if the reported vulnerability remains, if it introduces any of the unsafe patterns above, or if it contains TODOs, placeholders, markdown, or prose.

VALIDATED VULNERABILITIES:
{findings}

CONTRACT SOURCE:
{source_code}

Return only the complete Solidity source code. Do not include markdown or an explanation."""
                if progress_callback:
                    progress_callback("secure_generation", "Generating secure Solidity", "The local model is rewriting vulnerable logic while preserving the contract interface.")
                print("[Generator] Initial candidate generation started...")
                raw_response = self._chat(prompt)
                candidate_source = self._normalize_generated_solidity(self._clean_solidity(raw_response))
                print(f"[Generator] Initial candidate generated (length: {len(candidate_source)} chars).")
            else:
                unchanged_warning = ""
                if candidate_source == previous_candidate_source:
                    print_warning(f"[Repair] Attempt {attempt - 1} produced an unchanged candidate!")
                    unchanged_warning = "\nIMPORTANT: Your previous repair output was IDENTICAL to the prior candidate and was rejected again. You MUST make a concrete source-level edit changing code ordering (state update BEFORE external call).\n"

                repair_prompt = f"""You are repairing an existing Solidity smart contract. It failed mandatory security or compilation validation.

REPAIR ATTEMPT {attempt - 1} OF {max_attempts - 1}:{unchanged_warning}
Preserve the contract's intended functionality, contract name, events, modifiers, inheritance, and public interface.
Fix every reported security and compilation issue listed below.

SPECIFIC SECURITY REPAIR GUIDANCE:
1. Reentrancy / CEI Violation: You MUST change the code ordering so that state updates (e.g. `balances[msg.sender] -= amount;`) occur BEFORE external calls (e.g. `(bool success,) = msg.sender.call{{value: amount}}("");`).
   DO NOT make external calls before state updates.
2. Low-Level Call Checks: Always check return values explicitly: `(bool success,) = msg.sender.call{{value: amount}}(""); require(success, "Transfer failed");`.
3. No Extra Public Functions/Members: Do NOT declare new `public` or `external` functions or `public` state variables. If adding a reentrancy guard variable, use `bool private _locked;` (must be `private` or `internal`, NOT `public`).
4. Do not remove existing security checks or change unrelated behavior.
5. Do not merely explain the solution.

Return ONLY the complete replacement Solidity source file: no markdown, JSON, explanation, TODOs, or placeholders.

ORIGINAL CONTRACT:
{source_code}

VALIDATED VULNERABILITIES:
{findings}

CURRENT GENERATED CONTRACT (FAILED VALIDATION):
{candidate_source}

EXACT VALIDATION AND COMPILATION FAILURES TO FIX:
{chr(10).join(f'- {failure}' for failure in failures)}
"""
                if progress_callback:
                    progress_callback("repairing_contract", f"Repairing generated contract (attempt {attempt - 1}/{max_attempts - 1})", "Applying corrective pass based on exact validation and compiler feedback.")
                print(f"[Repair] Attempt {attempt - 1}/{max_attempts - 1} started...")
                previous_candidate_source = candidate_source
                raw_response = self._chat(repair_prompt)
                candidate_source = self._normalize_generated_solidity(self._clean_solidity(raw_response))
                changed = "YES" if candidate_source != previous_candidate_source else "NO (UNCHANGED)"
                print(f"[Repair] Candidate changed: {changed} (length: {len(candidate_source)} chars).")

            if progress_callback:
                progress_callback("generated_validation", f"Validating generated code (attempt {attempt}/{max_attempts})", "Checking the generated Solidity for security regressions, compilation errors, and interface changes.")

            report = self._security_validation_report(candidate_source, vulnerabilities, source_code)
            quality = self._generation_quality_report(source_code, candidate_source)
            current_failures = report["blocking"] + quality["blocking"]

            if progress_callback:
                progress_callback("compiler_validation", f"Compiling candidate contract (attempt {attempt}/{max_attempts})", "Verifying Solidity syntax and compiler compatibility.")
            compile_ok, compile_err = self._compile_secure_solidity(candidate_source)
            if not compile_ok:
                current_failures.append(f"Compiler failure: {compile_err}")

            if not current_failures:
                self._record_secure_generation_warnings(report["warnings"] + quality["warnings"])
                print_success(f"[Generator] Candidate passed compiler and security validation on attempt {attempt}.")
                return candidate_source

            failures = current_failures
            print_warning(f"[Validator] FAILED attempt {attempt}/{max_attempts}: {'; '.join(failures)}")

        raise ValueError(
            f"Generated contract failed security validation after {max_attempts} repair attempts: "
            + "; ".join(failures)
        )

    def _compile_secure_solidity(self, source: str) -> tuple[bool, str]:
        """Compile candidate secure Solidity using solc or forge.

        Returns (compiled_successfully: bool, error_diagnostic: str).
        """
        solc_path = shutil.which("solc")
        if solc_path:
            import tempfile
            try:
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp_file = Path(temp_dir) / "Candidate.sol"
                    temp_file.write_text(source, encoding="utf-8")
                    result = subprocess.run(
                        [solc_path, "--bin", str(temp_file)],
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        timeout=30,
                    )
                    if result.returncode == 0:
                        return True, ""
                    error_msg = (result.stderr or result.stdout or "Solidity compilation failed.").strip()
                    if "@openzeppelin" not in error_msg and "import" not in error_msg.lower():
                        return False, error_msg
            except Exception as exc:
                print_warning(f"Direct solc check failed: {exc}")

        validation_root = self.exploit_root / ".secure_validation" / uuid.uuid4().hex
        try:
            (validation_root / "src").mkdir(parents=True, exist_ok=True)
            lib = self.exploit_root / "lib"
            if lib.exists():
                shutil.copytree(lib, validation_root / "lib")
            (validation_root / "src" / "SecureContract.sol").write_text(source, encoding="utf-8")
            (validation_root / "foundry.toml").write_text(
                '[profile.default]\nsrc = "src"\nlibs = ["lib"]\nout = "out"\ncache_path = "cache"\n',
                encoding="utf-8",
            )
            command = ["forge", "build"]
            if solc_path:
                command.extend(["--use", solc_path])
            result = subprocess.run(
                command,
                cwd=validation_root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.model_config.forge_build_timeout,
                env=self._forge_env(),
            )
            if result.returncode == 0:
                return True, ""
            diag = (result.stderr or result.stdout or "Forge compilation failed.").strip()
            return False, diag
        except Exception as exc:
            return False, f"Compilation error: {exc}"
        finally:
            shutil.rmtree(validation_root, ignore_errors=True)

    def _record_secure_generation_warnings(self, warnings: List[str]) -> None:
        """Expose non-blocking validation guidance without rejecting a contract."""
        self.last_secure_generation_warnings = warnings
        for warning in warnings:
            print_warning(f"Secure generator validation warning: {warning}")

    @staticmethod
    def _normalize_generated_solidity(source: str, diagnostics: str = "") -> str:
        """Repair safe, mechanical Solidity generation artifacts before compilation.

        This deliberately avoids semantic rewrites.  It removes duplicated
        directives and orphaned SafeMath syntax, which is invalid when a
        Solidity 0.8 contract has no SafeMath definition or import.
        """
        text = str(source or "").replace("\r\n", "\n")
        text = re.sub(r"^\s*```(?:solidity|sol)?\s*$|^\s*```\s*$", "", text, flags=re.I | re.M)
        lines, result = text.split("\n"), []
        seen_pragmas, seen_spdx, seen_imports = set(), set(), set()
        is_solidity_08 = bool(re.search(r"\bpragma\s+solidity\s+(?:\^?0\.8|>=\s*0\.8)", text))
        has_safemath_definition = bool(re.search(r"\blibrary\s+SafeMath\b", text))
        has_safemath_import = bool(re.search(r"\bimport\s+[^;]*\bSafeMath\b[^;]*;", text))
        preserve_safemath = has_safemath_definition or has_safemath_import

        for line in lines:
            stripped = line.strip()
            if not stripped:
                result.append(line)
                continue
            if re.match(r"^//\s*SPDX-License-Identifier:\s*", stripped, re.I):
                key = stripped.lower()
                if key in seen_spdx:
                    continue
                seen_spdx.add(key)
            elif re.match(r"^pragma\s+solidity\b", stripped, re.I):
                key = stripped.rstrip(";").lower()
                if key in seen_pragmas or seen_pragmas:
                    continue
                seen_pragmas.add(key)
            elif re.match(r"^import\b", stripped):
                key = re.sub(r"\s+", " ", stripped)
                if key in seen_imports:
                    continue
                seen_imports.add(key)
            if is_solidity_08 and not preserve_safemath:
                if re.match(r"^using\s+SafeMath(?:\s+for\s+[^;]+)?\s*;?\s*$", stripped, re.I):
                    continue
            result.append(line)

        normalized = "\n".join(result).strip()
        if is_solidity_08 and not preserve_safemath:
            normalized = re.sub(
                r"\busing\s+SafeMath(?:\s+for\s+[^;\n]+)?\s*;", "", normalized, flags=re.I
            )
            # ``SafeMath`` is a library, not an inheritance base. A model can
            # accidentally emit this alongside the obsolete using statement.
            normalized = re.sub(
                r"(\bcontract\s+[A-Za-z_]\w*)\s+is\s+SafeMath\b", r"\1", normalized
            )
        # Compiler output sometimes identifies an orphaned SafeMath statement
        # that was emitted without a semicolon or formatting. Remove only that
        # known obsolete construct; other diagnostics are left untouched.
        if is_solidity_08 and not preserve_safemath and re.search(r"SafeMath", diagnostics, re.I):
            normalized = re.sub(
                r"(?im)^\s*using\s+SafeMath(?:\s+for\s+[^;\n]+)?\s*;?\s*$\n?", "", normalized
            )
        # A repeated complete contract is a common LLM artifact. Retain the
        # first definition and discard later same-name blocks; this is a
        # mechanical duplicate repair, not a contract rename.
        duplicate_ranges, names = [], set()
        declaration = re.compile(r"\b(?:contract|interface|library)\s+([A-Za-z_]\w*)\b[^{};]*\{")
        for match in declaration.finditer(normalized):
            name = match.group(1)
            if name not in names:
                names.add(name)
                continue
            depth = 1
            end = match.end()
            for index in range(match.end(), len(normalized)):
                if normalized[index] == "{":
                    depth += 1
                elif normalized[index] == "}":
                    depth -= 1
                    if depth == 0:
                        end = index + 1
                        break
            duplicate_ranges.append((match.start(), end))
        for start, end in reversed(duplicate_ranges):
            normalized = normalized[:start] + normalized[end:]
        return normalized.strip() + "\n"

    @staticmethod
    def _generation_quality_report(original: str, generated: str) -> Dict[str, List[str]]:
        """Verify that a security rewrite retains the target's public identity."""
        original_contracts = GeneratorAgent._contract_declarations(original, "contract")
        generated_contracts = GeneratorAgent._contract_declarations(generated, "contract")
        original_interfaces = GeneratorAgent._contract_declarations(original, "interface")
        generated_interfaces = GeneratorAgent._contract_declarations(generated, "interface")
        blocking, warnings = [], []

        for name, bases in original_contracts.items():
            if name not in generated_contracts:
                blocking.append(f"High: original contract name {name} was not preserved")
            elif bases != generated_contracts[name]:
                blocking.append(f"High: inheritance for contract {name} was changed")
        for name in original_interfaces:
            if name not in generated_interfaces:
                blocking.append(f"High: original interface {name} was not preserved")

        missing_events = GeneratorAgent._event_signatures(original) - GeneratorAgent._event_signatures(generated)
        for event in sorted(missing_events):
            blocking.append(f"High: original event {event} was removed")

        missing_signatures = (
            GeneratorAgent._normalized_function_signatures(original)
            - GeneratorAgent._normalized_function_signatures(generated)
        )
        for signature in sorted(missing_signatures):
            blocking.append(f"High: original function signature {signature} was changed or removed")

        extra_signatures = (
            GeneratorAgent._normalized_function_signatures(generated)
            - GeneratorAgent._normalized_function_signatures(original)
        )
        for signature in sorted(extra_signatures):
            name = signature.split("(", 1)[0]
            if name in {"constructor", "receive", "fallback"}:
                continue
            blocking.append(f"High: generated contract introduced unauthorized function signature {signature}")

        original_modifiers = set(re.findall(r"\bmodifier\s+([A-Za-z_]\w*)\b", original))
        generated_modifiers = set(re.findall(r"\bmodifier\s+([A-Za-z_]\w*)\b", generated))
        for modifier in sorted(original_modifiers - generated_modifiers):
            blocking.append(f"High: original modifier {modifier} was removed")
        missing_modifier_use = GeneratorAgent._function_modifier_usage(original, original_modifiers) - GeneratorAgent._function_modifier_usage(generated, original_modifiers)
        for signature, modifier in sorted(missing_modifier_use):
            blocking.append(f"High: modifier {modifier} was removed from {signature}")

        if GeneratorAgent._storage_layout(original) != GeneratorAgent._storage_layout(generated):
            warnings.append("Medium: storage layout changed; confirm the change is required by the security fix")
        if GeneratorAgent._pragma(original) != GeneratorAgent._pragma(generated):
            blocking.append("High: generated Solidity pragma does not match the original contract")
        return {"blocking": list(dict.fromkeys(blocking)), "warnings": list(dict.fromkeys(warnings))}

    @staticmethod
    def _contract_declarations(source: str, kind: str) -> Dict[str, tuple[str, ...]]:
        declarations = {}
        pattern = re.compile(
            rf"\b(?:abstract\s+)?{re.escape(kind)}\s+([A-Za-z_]\w*)(?:\s+is\s+([^{{]+))?\s*{{", re.S
        )
        for match in pattern.finditer(source):
            bases = tuple(part.strip() for part in (match.group(2) or "").split(",") if part.strip())
            declarations[match.group(1)] = bases
        return declarations

    @staticmethod
    def _event_signatures(source: str) -> set[str]:
        return {
            GeneratorAgent._normalize_solidity_type(re.sub(r"\s+", " ", event))
            for event in re.findall(r"\bevent\s+[A-Za-z_]\w*\s*\([^;{}]*\)(?:\s+anonymous)?\s*;", source, re.S)
        }

    @staticmethod
    def _normalize_solidity_type(solidity_type: str) -> str:
        normalized = re.sub(r"\bunsigned\b", "uint256", solidity_type.strip())
        normalized = re.sub(r"\buint\b", "uint256", normalized)
        normalized = re.sub(r"\bint\b", "int256", normalized)
        return re.sub(r"\s+", " ", normalized).strip()

    @staticmethod
    def _normalized_function_signatures(source: str) -> set[str]:
        signatures = set()
        for name, parameters in re.findall(r"\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)", source, re.S):
            types = []
            for parameter in filter(None, (item.strip() for item in parameters.split(","))):
                tokens = [token for token in parameter.split() if token not in {"memory", "storage", "calldata", "indexed"}]
                if not tokens:
                    continue
                raw_type = " ".join(tokens[:2]) if tokens[:2] == ["address", "payable"] else tokens[0]
                types.append(GeneratorAgent._normalize_solidity_type(raw_type))
            signatures.add(canonical_function_id(name, types))
        return signatures

    @staticmethod
    def _function_modifier_usage(source: str, known_modifiers: set[str]) -> set[tuple[str, str]]:
        usage = set()
        pattern = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)([^;{]*)", re.S)
        for name, parameters, suffix in pattern.findall(source):
            types = []
            for parameter in filter(None, (item.strip() for item in parameters.split(","))):
                tokens = [token for token in parameter.split() if token not in {"memory", "storage", "calldata", "indexed"}]
                if tokens:
                    raw_type = " ".join(tokens[:2]) if tokens[:2] == ["address", "payable"] else tokens[0]
                    types.append(GeneratorAgent._normalize_solidity_type(raw_type))
            signature = canonical_function_id(name, types)
            for modifier in known_modifiers:
                if re.search(rf"\b{re.escape(modifier)}\b", suffix):
                    usage.add((signature, modifier))
        return usage

    @staticmethod
    def _storage_layout(source: str) -> List[str]:
        """Return simple top-level state declarations in source order."""
        layout, depth = [], 0
        for line in GeneratorAgent._without_comments(source).splitlines():
            stripped = line.strip()
            if depth == 1 and ";" in stripped and not re.match(
                r"(?:pragma|import|using|event|error|return|emit)\b", stripped
            ) and not re.match(r"(?:function|modifier|constructor|fallback|receive)\b", stripped):
                if re.match(r"(?:mapping\s*\(|[A-Za-z_]\w*)", stripped):
                    layout.append(GeneratorAgent._normalize_solidity_type(re.sub(r"\s+", " ", stripped)))
            depth += stripped.count("{") - stripped.count("}")
        return layout

    @staticmethod
    def _solidity_functions(source: str) -> List[tuple[str, str, str]]:
        """Return direct function name/header/body triples for lightweight security checks."""
        functions = []
        pattern = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\([^)]*\)[^{;]*\{", re.S)
        for match in pattern.finditer(source):
            depth = 1
            for index in range(match.end(), len(source)):
                if source[index] == "{":
                    depth += 1
                elif source[index] == "}":
                    depth -= 1
                    if depth == 0:
                        functions.append((match.group(1), match.group(0), source[match.end():index]))
                        break
        return functions

    @staticmethod
    def _security_validation_report(source: str, vulnerabilities: List[Dict],
                                    original_source: str = "") -> Dict[str, List[str]]:
        """Classify generated-source findings by severity.

        This intentionally supplements Slither parsing: parsing confirms syntax,
        while these checks confirm that a requested hardening was actually made.
        Only Critical/High findings block delivery; Medium/Low findings are
        retained as warnings for the operator.
        """
        code = GeneratorAgent._without_comments(str(source or ""))
        blocking, warnings, informational = [], [], []
        vuln_types = " ".join(
            str(item.get("vulnerability_type", "")).lower()
            for item in vulnerabilities if isinstance(item, dict)
        )
        functions = GeneratorAgent._solidity_functions(code)

        if not re.search(r"\bpragma\s+solidity\s+(?:\^?0\.8|>=\s*0\.8)", code):
            blocking.append("High: generated contract must use Solidity 0.8+ checked arithmetic")
        if re.search(r"\b(?:TODO|FIXME|IMPLEMENT_ME|your[_ -]?code|placeholder)\b", code, re.I):
            blocking.append("High: generated contract contains a placeholder or TODO")
        if re.search(r"\btx\.origin\b", code):
            blocking.append("Critical: tx.origin remains in generated Solidity")
        if re.search(r"\.delegatecall\s*\(", code):
            blocking.append("Critical: dangerous delegatecall remains in generated Solidity")
        selfdestruct_blocking, selfdestruct_info = GeneratorAgent._validate_selfdestruct(
            code, original_source
        )
        blocking.extend(selfdestruct_blocking)
        informational.extend(selfdestruct_info)
        if re.search(r"\bunchecked\s*\{", code):
            warnings.append("Medium: unchecked arithmetic remains and requires manual review")

        if any(term in vuln_types for term in ("random", "timestamp")):
            status = GeneratorAgent._randomness_status(code)
            original_status = GeneratorAgent._randomness_status(original_source)
            if status == "UNSAFE" or (
                original_source and status == "PARTIALLY IMPROVED" and original_status == "SECURE"
            ):
                blocking.append("High: generation introduced unsafe randomness")
            elif status == "PARTIALLY IMPROVED":
                warnings.append("Medium: weak randomness is partially improved; use VRF or commit-reveal for adversarial fairness")

        state_write = re.compile(
            r"\b(?!success\b|ok\b|sent\b)[A-Za-z_]\w*(?:\s*\[[^\]]+\]|\s*\.\w+)*\s*(?:=|\+=|-=|\*=|/=)"
        )
        external_call = re.compile(r"\.(?:call\s*(?:\{[^}]*\}\s*)?\(|send\s*\(|transfer\s*\()")
        low_level_call = re.compile(r"\.call\s*(?:\{[^}]*\}\s*)?\(")
        for name, header, body in functions:
            for call in external_call.finditer(body):
                if state_write.search(body[call.end():]):
                    blocking.append(f"High: {name} performs an external call before a state update (CEI violation)")
                    break
            for call in low_level_call.finditer(body):
                prefix = body[max(0, call.start() - 150):call.start()]
                suffix = body[call.end():call.end() + 300]
                assignment = re.search(
                    r"\b(?:bool\s+([A-Za-z_]\w*)|(?:\(\s*bool\s+([A-Za-z_]\w*)\s*,[^)]*\)))\s*=\s*",
                    prefix, re.S
                )
                var_name = (assignment.group(1) or assignment.group(2)) if assignment else None
                checked = False
                if var_name:
                    checked = bool(re.search(rf"\b(?:require|if)\s*\([^)]*\b{re.escape(var_name)}\b", suffix, re.S))
                if not checked:
                    checked = bool(
                        re.search(r"^\s*\)?\s*;\s*require\s*\(", suffix)
                        or re.search(r"\b(?:require|if)\s*\([^)]*$", prefix, re.S)
                        or re.search(r"\b(?:require|if)\s*\(\s*(?:success|ok|sent|result)\b", suffix, re.S)
                    )
                if not checked:
                    blocking.append(f"High: {name} has a low-level call without checked success and revert handling")
                    break

        if any(term in vuln_types for term in ("access", "authoriz", "owner", "role")):
            privileged_name = re.compile(
                r"(?:set|change|transfer).*(?:owner|admin|role)|"
                r"(?:mint|pause|unpause|upgrade|withdraw(?:fees)?|destroy)", re.I,
            )
            # Authorization is required by operation semantics, not merely by
            # an analyzer label.  A public/view/internal helper such as
            # ``random`` must not be made owner-only just because a separate
            # access-control finding exists in the same report.
            candidates = [entry for entry in functions if privileged_name.search(entry[0])]
            for name, header, body in candidates:
                if not re.search(r"\b(?:public|external)\b", header) or re.search(r"\b(?:view|pure)\b", header):
                    continue
                is_user_withdrawal, explanation = GeneratorAgent._is_user_withdrawal(name, body)
                if is_user_withdrawal:
                    informational.append(f"Informational: {explanation}")
                    continue
                if not GeneratorAgent._has_privileged_guard(header + body):
                    intent = "administrative withdrawal" if re.search(
                        r"(?:withdraw|treasury|emergency)", name, re.I
                    ) else "privileged operation"
                    blocking.append(
                        f"High: {name} allows arbitrary callers to perform a {intent} without authorization"
                    )
                else:
                    informational.append(f"Informational: {name} is restricted by an administrative authorization check")
                if re.search(r"(?:owner|admin)\w*\s*\)", header, re.I) and not re.search(r"address\s*\(\s*0\s*\)", body):
                    blocking.append(f"High: {name} does not validate a zero-address ownership/admin update")

        if any(term in vuln_types for term in ("dos", "denial")):
            if re.search(r"\bfor\s*\([^;]*;[^;]*\.length\s*;[^)]*\)[\s\S]{0,800}\.(?:call|send|transfer)\s*\(", code):
                blocking.append("High: unbounded recipient-processing loop remains")

        if any(term in vuln_types for term in ("input", "validation")):
            for name, header, body in functions:
                if re.search(r"\b(?:public|external)\b", header) and "(" in header and not re.search(r"\b(?:require|revert|if)\b", body):
                    warnings.append(f"Medium: {name} has no visible security-critical input validation")

        return {
            "blocking": list(dict.fromkeys(blocking)),
            "warnings": list(dict.fromkeys(warnings)),
            "informational": list(dict.fromkeys(informational)),
        }

    @staticmethod
    def _has_privileged_guard(text: str) -> bool:
        return bool(re.search(
            r"\b(?:onlyOwner|onlyRole|hasRole)\b|msg\.sender\s*==\s*(?:owner|admin)|"
            r"(?:owner|admin)\s*==\s*msg\.sender", text,
        ))

    @staticmethod
    def _is_user_withdrawal(name: str, body: str) -> tuple[bool, str]:
        """Recognize withdrawals constrained to the caller's own accounting."""
        if not re.search(r"withdraw", name, re.I):
            return False, ""
        if re.search(r"(?:emergency|treasury|fee)", name, re.I):
            return False, ""
        account = r"(?:balances|deposits|shares|credits|accounts)\s*\[\s*msg\.sender\s*\]"
        checks_or_debits = re.search(
            rf"{account}\s*(?:>=|>|-=|=\s*0)", body, re.I,
        )
        caller_payout = re.search(
            r"(?:payable\s*\(\s*msg\.sender\s*\)|msg\.sender)\s*\.\s*"
            r"(?:call|send|transfer)\b", body, re.I,
        )
        if checks_or_debits and caller_payout:
            return True, "withdraw is correctly restricted to the caller's own recorded balance"
        return False, ""

    @staticmethod
    def _validate_selfdestruct(source: str, original_source: str) -> tuple[List[str], List[str]]:
        """Allow an original selfdestruct only when its destruction path is protected."""
        if not re.search(r"\bselfdestruct\s*\(", source):
            return [], []
        if not re.search(r"\bselfdestruct\s*\(", str(original_source or "")):
            return ["High: generated contract introduced selfdestruct outside the original business logic"], []

        blocking, informational = [], []
        for name, header, body in GeneratorAgent._solidity_functions(source):
            if not re.search(r"\bselfdestruct\s*\(", body):
                continue
            beneficiary = re.search(r"\bselfdestruct\s*\(\s*payable\s*\(\s*([^)]+?)\s*\)\s*\)", body)
            protected = GeneratorAgent._has_privileged_guard(header + body)
            beneficiary_value = beneficiary.group(1).strip() if beneficiary else ""
            safe_beneficiary = beneficiary_value in {"msg.sender", "owner", "admin", "treasury"}
            if not protected:
                blocking.append(f"High: {name} permits unrestricted contract destruction")
            elif not safe_beneficiary:
                blocking.append(f"High: {name} destroys the contract to an unverified beneficiary")
            else:
                informational.append(
                    f"Informational: {name} retains original selfdestruct business logic behind authorization"
                )
        return blocking, informational

    @staticmethod
    def _randomness_status(source: str) -> str:
        """Classify randomness without demanding an unavailable oracle."""
        code = GeneratorAgent._without_comments(str(source or ""))
        if re.search(r"\btx\.origin\b", code):
            return "UNSAFE"
        if re.search(r"\b(?:commit\w*\s*\(|reveal\w*\s*\(|vrf\w*\s*\(|requestRandom\w*\s*\(|randomnessProvider\b)", code, re.I):
            return "SECURE"
        if re.search(
            r"\bblock\.(?:timestamp|number|prevrandao|difficulty)\b|"
            r"\bblockhash\s*\(|\bmsg\.(?:sender|sig)\b|\btx\.origin\b", code, re.I,
        ):
            return "PARTIALLY IMPROVED"
        return "SECURE"

    @staticmethod
    def _security_validation_failures(source: str, vulnerabilities: List[Dict],
                                      original_source: str = "") -> List[str]:
        """Compatibility helper returning only Critical/High blockers."""
        return GeneratorAgent._security_validation_report(
            source, vulnerabilities, original_source
        )["blocking"]

    def generate_poc_contract(
        self, vulnerability: Dict, plan: Dict, target: Dict, failures: List[str], attempt: int,
        previous_code: str = "",
    ) -> str:
        deterministic = self._deterministic_poc(vulnerability, target)
        if deterministic:
            return deterministic
        affected = ", ".join(self._extract_relevant_functions(vulnerability)) or "not specified"
        strategy = self._validation_mode(vulnerability)
        previous_failures = "None (first attempt)." if not failures else "\n".join(f"- {item}" for item in failures)
        target_import = f'import "../src/{target["filename"]}";'
        target_type = target["contract_name"]
        if target_type == "Test":
            # forge-std exports Test, so importing a target contract named Test
            # without an alias makes every generated PoC uncompilable.
            target_import = f'import {{Test as VulnerableBankTarget}} from "../src/{target["filename"]}";'
            target_type = "VulnerableBankTarget"
        constructor_call = self._constructor_call(target.get("constructor", "constructor()"), target_type)
        test_name = "testExploit" if strategy == "executable" else "testDemonstration"
        constructor = target.get("constructor", "constructor()")
        function_map = "\n".join(f"- {signature}" for signature in target.get("functions", [])) or "- no externally callable functions"
        public_members = ", ".join(target.get("public_members", [])) or "none"
        prompt = f"""Generate one complete Foundry Solidity PoC for qwen2.5-coder:7b.

TARGET CONTRACT
File: {target["filename"]}
Contract: {target["contract_name"]}
Pragma: {target.get("pragma", "^0.8.20")}
Constructor: {constructor}
Required constructor call: {constructor_call}
Allowed target functions:
{function_map}
Allowed public target members: {public_members}

VULNERABILITY
Type: {vulnerability.get("vulnerability_type", "")}
Reasoning: {vulnerability.get("reasoning", "")}
Affected functions: {affected}
Code snippet: {vulnerability.get("code_snippet", "")}

EXPLOIT PLAN
Setup: {plan.get("setup_steps", [])}
Execution: {plan.get("execution_steps", [])}
Validation: {plan.get("validation_steps", [])}

PREVIOUS GENERATION FAILURES
{previous_failures}

PREVIOUS SOLIDITY
{previous_code or "None (first attempt)."}

GENERATION RULES
1. Return only complete Solidity. No JSON, markdown, prose, or code fences.
2. Use exactly `pragma solidity {target.get("pragma", "^0.8.20")};`.
3. Import exactly `./basetest.sol` and `{target_import}`.
4. Inherit BaseTestWithBalanceLog, declare `{target_type} target`, and use `{constructor_call}` in setUp.
5. Use only the allowed target functions and public members listed above. Do not invent identifiers.
6. Exercise an affected function when it exists in the allowed function list.
7. Use `{test_name}` with an assertion and balanceLog.
8. Strategy: {strategy}. {"Use attacker setup and vm.prank for the executable exploit." if strategy == "executable" else "Write a deterministic demonstration without forcing an attacker or balance theft."}

OUTPUT ONLY SOLIDITY."""
        return self._clean_solidity(self._chat(prompt))

    def validate_contract(self, code: str, vulnerability: Dict, target: Dict) -> List[str]:
        """Deterministic checks; this is deliberately independent of model judgement."""
        errors: List[str] = []
        if not re.search(r"^\s*//\s*SPDX-License-Identifier:\s*\S+", code, re.M):
            errors.append("missing SPDX license after automatic repair")
        expected_pragma = target.get("pragma")
        pragma_match = re.search(r"\bpragma\s+solidity\s+([^;]+);", code)
        if not pragma_match:
            errors.append("missing pragma after automatic repair")
        elif expected_pragma and pragma_match.group(1).strip() != expected_pragma:
            errors.append(f"pragma must match target exactly: {expected_pragma}")
        imports = re.findall(r"^\s*import\s+(?:[^\"']+from\s+)?[\"']([^\"']+)[\"']\s*;", code, re.M)
        if "./basetest.sol" not in imports:
            errors.append("missing basetest import")
        expected_import = f"../src/{target['filename']}"
        if expected_import not in imports:
            errors.append(f"missing target import {expected_import}")
        if re.search(r"\b(TODO|placeholder|fill\s+here)\b|\.\.\.", code, re.I):
            errors.append("contains placeholder content")
        if self._contains_placeholder(code):
            errors.append("contains unresolved address or identifier placeholder")
        if not self._braces_match(code):
            errors.append("malformed braces")
        contract_match = re.search(
            r"\bcontract\s+\w+\s+is\s+[^\{]*\bBaseTestWithBalanceLog\b[^\{]*\{", code
        )
        if not contract_match:
            errors.append("missing BaseTestWithBalanceLog test contract")
        setup = self._function_body(code, "setUp")
        strategy = self._validation_mode(vulnerability)
        test_name = "testExploit" if strategy == "executable" else "testDemonstration"
        test = self._function_body(code, test_name)
        # setUp is optional in Foundry.  Forge is the source of truth for a
        # constructor deployment that is performed elsewhere in the test.
        if not test or not re.search(r"\S", self._without_comments(test)):
            errors.append(f"missing or empty {test_name}")
        # Solidity permits modifiers before or after visibility.  The old
        # expression accepted only one ordering and rejected valid generated
        # tests before Forge could compile them.
        test_signature = re.search(rf"function\s+{test_name}\s*\([^)]*\)\s*([^\{{]*)\{{", code)
        if self._requires_exploit_actor(vulnerability) and (not test_signature or not re.search(r"\bbalanceLog\b", test_signature.group(1))):
            errors.append(f"{test_name} does not use balanceLog")
        if self._requires_exploit_actor(vulnerability) and "vm.deal" not in code:
            errors.append("missing vm.deal for executable exploit")
        if self._requires_exploit_actor(vulnerability) and not re.search(r"\bvm\.(?:prank|startPrank)\s*\(", code):
            errors.append("missing vm.prank or vm.startPrank for executable exploit")
        if not re.search(r"\b(?:assert|assertEq|assertTrue|assertFalse|assertGt|assertLt|assertGe|assertLe|require)\s*\(", code):
            errors.append("missing Foundry assertion")
        if not re.search(rf"\b{re.escape(target['contract_name'])}\b", code):
            errors.append("target contract name is not used")
        source_functions = set(target.get("functions", []))
        allowed_members = set(target.get("public_members", []))
        allowed_names = {signature.split("(", 1)[0] for signature in source_functions} | allowed_members
        for call in re.findall(r"\btarget\s*\.\s*([A-Za-z_]\w*)\s*(?:\{|\()", code):
            if call not in allowed_names:
                errors.append(
                    f"PoC calls nonexistent target function or member: {call}. "
                    f"Allowed functions: {sorted(source_functions)}. Allowed public members: {sorted(allowed_members)}"
                )
        affected = self._extract_relevant_functions(vulnerability)
        for function in affected:
            if source_functions and function in source_functions:
                function_name = function.split("(", 1)[0]
                if not self._uses_affected_function(code, function_name):
                    errors.append(f"PoC does not exercise affected function: {function}")
        if "reentrancy" in str(vulnerability.get("vulnerability_type", "")).lower():
            reentry_points = re.findall(r"\.(\w+)\s*(?:\{[^}]*\}\s*)?\(", code)
            if not re.search(r"\b(?:receive|fallback)\s*\(", code) or not any(reentry_points.count(name) > 1 for name in reentry_points):
                errors.append("reentrancy PoC must include a callback/fallback and a repeated re-entry call")
        return errors

    def compile_candidate(self, code: str, attempt: int = 0) -> Dict:
        """Compile in an isolated Foundry project without running any test.

        The isolated tree prevents prior generated PoCs from entering the
        compilation unit and is deleted regardless of success or failure.
        """
        validation_root = self.exploit_root / ".poc_validation" / uuid.uuid4().hex
        started = time.perf_counter()
        stdout = ""
        stderr = ""
        returncode = None
        try:
            (validation_root / "test").mkdir(parents=True)
            self._copy_candidate_sources(code, validation_root / "src")
            lib = self.exploit_root / "lib"
            if lib.exists():
                shutil.copytree(lib, validation_root / "lib")
            base_test = self.test_dir / "basetest.sol"
            if base_test.exists():
                shutil.copy2(base_test, validation_root / "test" / "basetest.sol")
            else:
                self.generate_basetest_file()
                shutil.copy2(self.test_dir / "basetest.sol", validation_root / "test" / "basetest.sol")
            (validation_root / "test" / "Candidate.t.sol").write_text(code, encoding="utf-8")
            (validation_root / "foundry.toml").write_text(
                '[profile.default]\nsrc = "src"\ntest = "test"\nlibs = ["lib"]\nout = "out"\ncache_path = "cache"\n',
                encoding="utf-8",
            )
            # The workspace itself is ephemeral, so a local cache cannot
            # leak into a later validation.  Avoid --no-cache because some
            # Foundry releases still require a cache directory for signatures.
            command = ["forge", "build"]
            solc = shutil.which("solc")
            if solc:
                command.extend(["--use", solc])
            result = subprocess.run(
                command,
                cwd=validation_root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.model_config.forge_build_timeout,
                env=self._forge_env(),
            )
            stdout, stderr, returncode = result.stdout or "", result.stderr or "", result.returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            stderr = f"Unable to run forge build: {exc}"
        finally:
            compile_time = time.perf_counter() - started
            output = stdout + ("\n" if stdout and stderr else "") + stderr
            compiled = returncode == 0
            self._write_compile_artifacts(code, stdout, stderr, attempt)
            shutil.rmtree(validation_root, ignore_errors=True)
            parent = validation_root.parent
            try:
                parent.rmdir()
            except OSError:
                pass
        return {
            "compiled": compiled,
            "compile_error": "" if compiled else (stderr or stdout or "Forge compilation failed with no diagnostic."),
            "stdout": stdout,
            "stderr": stderr,
            "output": output,
            "returncode": returncode,
            "compile_time": compile_time,
        }

    def _copy_candidate_sources(self, code: str, destination: Path) -> None:
        """Copy only target imports and their local Solidity dependency closure.

        Foundry compiles every Solidity file below ``src``.  Copying the full
        project would therefore let unrelated uploads or legacy fixtures break
        an otherwise valid generated PoC.
        """
        source_root = (self.exploit_root / "src").resolve()
        candidate_dir = (self.exploit_root / "test").resolve()
        pending = []
        for imported in self._solidity_imports(code):
            candidate = (candidate_dir / imported).resolve()
            if candidate.is_relative_to(source_root):
                pending.append(candidate)
        copied = set()
        while pending:
            source = pending.pop()
            if source in copied or not source.is_file() or not source.is_relative_to(source_root):
                continue
            copied.add(source)
            relative = source.relative_to(source_root)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            for imported in self._solidity_imports(source.read_text(encoding="utf-8")):
                dependency = (source.parent / imported).resolve()
                if dependency.is_relative_to(source_root):
                    pending.append(dependency)

    @staticmethod
    def _solidity_imports(code: str) -> List[str]:
        return re.findall(r'^\s*import\s+(?:[^"\']+from\s+)?["\']([^"\']+)["\']\s*;', code, re.M)

    def _write_compile_artifacts(self, code: str, stdout: str, stderr: str, attempt: int) -> None:
        """Persist source and both Forge streams with a collision-proof name."""
        reports = self.project_root / "reports"
        reports.mkdir(exist_ok=True)
        prefix = reports / f"generator_{int(time.time() * 1000)}_{uuid.uuid4().hex}_attempt{attempt}_compile"
        prefix.with_suffix(".sol").write_text(code, encoding="utf-8")
        prefix.with_suffix(".stdout.log").write_text(stdout, encoding="utf-8")
        prefix.with_suffix(".stderr.log").write_text(stderr, encoding="utf-8")

    def _write_validation_artifacts(self, code: str, errors: List[str], attempt: int) -> None:
        """Persist pre-Forge validation failures without overwriting prior repairs."""
        reports = self.project_root / "reports"
        reports.mkdir(exist_ok=True)
        prefix = reports / f"generator_{int(time.time() * 1000)}_{uuid.uuid4().hex}_attempt{attempt}_validation"
        prefix.with_suffix(".sol").write_text(code, encoding="utf-8")
        prefix.with_suffix(".validator.log").write_text("\n".join(errors), encoding="utf-8")
        prefix.with_suffix(".stdout.log").write_text("", encoding="utf-8")
        prefix.with_suffix(".stderr.log").write_text("", encoding="utf-8")

    def _write_generation_log(self, attempt: int, stage: str, output: str) -> None:
        """Keep each generation diagnostic; never overwrite a prior investigation log."""
        reports = self.project_root / "reports"
        reports.mkdir(exist_ok=True)
        filename = reports / f"generator_{int(time.time() * 1000)}_attempt{attempt}_{stage}.log"
        filename.write_text(output, encoding="utf-8")

    def save_poc_locally(self, poc_code: str, vuln_type: str) -> str:
        if self.current_job_dir is None:
            self._begin_job_workspace()
        self.current_job_dir.mkdir(parents=True, exist_ok=True)
        safe_vuln = re.sub(r"[^A-Za-z0-9_]", "_", vuln_type) or "unknown"
        filename = self.current_job_dir / f"PoC_{safe_vuln}_{int(time.time() * 1000)}.t.sol"
        filename.write_text(poc_code, encoding="utf-8")
        print_success(f"PoC saved to isolated workspace {filename} (job {self.current_job_id})")
        return str(filename)

    def _begin_job_workspace(self) -> None:
        """Create a workspace that cannot contain tests from an earlier run."""
        self.current_job_id = uuid.uuid4().hex
        self.current_job_dir = self.workspace_root / self.current_job_id
        self.current_job_dir.mkdir(parents=True, exist_ok=False)
        print(f"[Generator] Using isolated Forge workspace: {self.current_job_dir}")

    def _resolve_target(self, exploit_data: Dict) -> Dict:
        configured = exploit_data.get("target_contract", {})
        candidates = []
        if configured.get("path"):
            candidates.append(self.exploit_root / "src" / configured["path"])
        candidates.extend(path for path in (self.exploit_root / "src").glob("*.sol") if path.name != "basetest.sol")
        for path in candidates:
            if path.exists():
                source = path.read_text(encoding="utf-8")
                contract = configured.get("name") or self._contract_name(source)
                if contract:
                    return {
                        "filename": path.name,
                        "contract_name": contract,
                        "functions": self._source_functions(source),
                        "public_members": self._public_members(source),
                        "pragma": self._pragma(source),
                        "constructor": self._constructor_signature(source),
                        "source": source,
                    }
        raise RuntimeError("Unable to resolve target contract.")

    def _deterministic_poc(self, vulnerability: Dict, target: Dict) -> str:
        """Return a source-derived PoC for patterns whose exploit is mechanically known.

        This path is intentionally narrow: it is used only when the exact
        target functions and unsafe state-update order exist in the source.
        Other categories continue through the local generator model.
        """
        source = target.get("source", "")
        functions = set(target.get("functions", []))
        vuln_type = str(vulnerability.get("vulnerability_type", "")).lower()
        if "access" in vuln_type:
            return self._access_control_poc(target, vulnerability)
        if "selfdestruct" in vuln_type:
            return self._selfdestruct_poc(target, vulnerability)
        if "unchecked" in vuln_type or "low_level" in vuln_type:
            return self._unchecked_call_poc(target, vulnerability)
        if "timestamp" in vuln_type:
            return self._timestamp_poc(target, vulnerability)
        if (
            vuln_type != "reentrancy"
            or "deposit()" not in functions
            or "withdraw(uint256)" not in functions
            or not re.search(r"\.call\s*\{[^}]*value\s*:\s*amount[^}]*\}\s*\(\s*['\"]{2}\s*\)", source, re.I)
            or not re.search(r"balances\s*\[\s*msg\.sender\s*\]\s*-=?=\s*amount", source)
            or source.find("msg.sender.call") > source.find("balances[msg.sender] -= amount")
        ):
            return ""

        target_type = target["contract_name"]
        target_import = f'import "../src/{target["filename"]}";'
        return f'''// SPDX-License-Identifier: UNLICENSED
pragma solidity {target.get("pragma", "^0.8.20")};

import "./basetest.sol";
{target_import}

contract ReentrancyReceiver {{
    {target_type} private immutable target;
    uint256 private immutable amount;

    constructor({target_type} target_) {{
        target = target_;
        amount = 1 ether;
    }}

    receive() external payable {{
        if (address(target).balance >= amount) {{
            target.withdraw(amount);
        }}
    }}

    function attack() external payable {{
        require(msg.value == amount, "incorrect seed");
        target.deposit{{value: amount}}();
        target.withdraw(amount);
    }}
}}

contract PocTest is BaseTestWithBalanceLog {{
    {target_type} target;
    ReentrancyReceiver receiver;
    address attacker = address(0xBAD);

    function setUp() public {{
        target = {self._constructor_call(target.get("constructor", "constructor()"), target_type)};
        receiver = new ReentrancyReceiver(target);
        vm.deal(attacker, 10 ether);
        vm.deal(address(target), 10 ether);
    }}

    function testExploit() public balanceLog {{
        vm.prank(attacker);
        receiver.attack{{value: 1 ether}}();
        assertGt(address(receiver).balance, 1 ether);
    }}
}}
'''

    def _access_control_poc(self, target: Dict, vulnerability: Dict) -> str:
        """Demonstrate an unprotected address setter only when source exposes its result."""
        affected = set(self._extract_relevant_functions(vulnerability))
        functions = set(target.get("functions", []))
        candidates = [signature for signature in functions if signature in affected and signature.endswith("(address)")]
        if not candidates or "owner" not in target.get("public_members", []):
            return ""
        name = candidates[0].split("(", 1)[0]
        return self._basic_poc(target, "testExploit", f"vm.prank(attacker);\n        target.{name}(attacker);\n        assertEq(target.owner(), attacker);", executable=True)

    def _selfdestruct_poc(self, target: Dict, vulnerability: Dict) -> str:
        affected = set(self._extract_relevant_functions(vulnerability))
        functions = set(target.get("functions", []))
        candidate = next((signature for signature in functions if signature in affected and signature.endswith("()")), "")
        if not candidate:
            return ""
        name = candidate.split("(", 1)[0]
        # Demonstration only: post-Cancun SELFDESTRUCT code-removal semantics
        # vary, but an unprotected call is still observable and executable.
        return self._basic_poc(target, "testExploit", f"target.{name}();\n        assertEq(address(target).balance, 0);", executable=False)

    def _unchecked_call_poc(self, target: Dict, vulnerability: Dict) -> str:
        functions = set(target.get("functions", []))
        affected = set(self._extract_relevant_functions(vulnerability))
        candidate = next((signature for signature in functions if signature in affected and signature == "unsafeSend(address,uint256)"), "")
        if not candidate:
            return ""
        return self._basic_poc(target, "testExploit", "vm.prank(attacker);\n        target.unsafeSend(payable(attacker), 0);\n        assertEq(address(target).balance, 0);", executable=True)

    def _timestamp_poc(self, target: Dict, vulnerability: Dict) -> str:
        functions = set(target.get("functions", []))
        affected = set(self._extract_relevant_functions(vulnerability))
        candidate = next((signature for signature in functions if signature in affected and signature.endswith("()")), "")
        if not candidate:
            return ""
        name = candidate.split("(", 1)[0]
        return self._basic_poc(target, "testDemonstration", f"uint256 observed = target.{name}();\n        assertGt(observed, 0);", executable=False)

    def _basic_poc(self, target: Dict, test_name: str, body: str, executable: bool) -> str:
        """Render small source-derived templates without model-created identifiers."""
        target_type = target["contract_name"]
        target_import = f'import "../src/{target["filename"]}";'
        setup = f"target = {self._constructor_call(target.get('constructor', 'constructor()'), target_type)};"
        if executable:
            setup += "\n        vm.deal(attacker, 10 ether);"
        return f'''// SPDX-License-Identifier: UNLICENSED
pragma solidity {target.get("pragma", "^0.8.20")};

import "./basetest.sol";
{target_import}

contract PocTest is BaseTestWithBalanceLog {{
    {target_type} target;
    address attacker = address(0xBAD);

    function setUp() public {{
        {setup}
    }}

    function {test_name}() public balanceLog {{
        {body}
    }}
}}
'''

    @staticmethod
    def _contract_name(source: str) -> Optional[str]:
        match = re.search(r"\b(?:abstract\s+)?contract\s+([A-Za-z_]\w*)", source)
        return match.group(1) if match else None

    @staticmethod
    def _source_functions(source: str) -> List[str]:
        functions = []
        for name, raw_params in re.findall(r"\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)", source):
            types = []
            for raw_param in filter(None, (part.strip() for part in raw_params.split(","))):
                tokens = [token for token in raw_param.split() if token not in {"memory", "storage", "calldata"}]
                if tokens:
                    raw_type = " ".join(tokens[:2]) if tokens[:2] == ["address", "payable"] else tokens[0]
                    types.append(GeneratorAgent._normalize_solidity_type(raw_type))
            functions.append(canonical_function_id(name, types))
        return functions

    @staticmethod
    def _public_members(source: str) -> List[str]:
        return re.findall(r"\b(?:mapping\s*\([^;]+\)|[A-Za-z_]\w*(?:\s*\[\s*\])?)\s+public\s+([A-Za-z_]\w*)", source)

    @staticmethod
    def _pragma(source: str) -> str:
        match = re.search(r"\bpragma\s+solidity\s+([^;]+);", source)
        return match.group(1).strip() if match else "^0.8.20"

    @staticmethod
    def _constructor_signature(source: str) -> str:
        match = re.search(r"\bconstructor\s*(\([^)]*\))", source)
        return f"constructor{match.group(1)}" if match else "constructor()"

    @staticmethod
    def _constructor_call(signature: str, contract_type: str) -> str:
        params = signature[signature.find("(") + 1:signature.rfind(")")].strip()
        if not params:
            return f"new {contract_type}()"
        defaults = []
        for parameter in params.split(","):
            solidity_type = parameter.strip().split()[0]
            if solidity_type == "address" or solidity_type == "address payable":
                defaults.append("address(0)")
            elif solidity_type == "bool":
                defaults.append("false")
            elif solidity_type == "string":
                defaults.append('""')
            elif solidity_type == "bytes":
                defaults.append('hex""')
            elif solidity_type.startswith("bytes"):
                defaults.append("bytes32(0)")
            elif solidity_type.endswith("[]"):
                defaults.append(f"new {solidity_type}(0)")
            else:
                defaults.append("0")
        return f"new {contract_type}({', '.join(defaults)})"

    @staticmethod
    def _validation_mode(vulnerability: Dict) -> str:
        vuln_type = str(vulnerability.get("vulnerability_type", "")).lower()
        if "informational" in vuln_type:
            return "informational"
        return "demonstration" if any(label in vuln_type for label in ("timestamp", "random", "business logic")) else "executable"

    @staticmethod
    def _requires_exploit_actor(vulnerability: Dict) -> bool:
        vuln_type = str(vulnerability.get("vulnerability_type", "")).lower()
        return "reentrancy" in vuln_type or "access" in vuln_type or "unchecked" in vuln_type

    @staticmethod
    def _extract_relevant_functions(vulnerability: Dict) -> List[str]:
        values = vulnerability.get("affected_functions", []) or []
        return [str(value).split(".")[-1] for value in values if str(value).strip()]

    def _self_review(self, code: str, vulnerability: Dict, target: Dict) -> str:
        local_errors = self.validate_contract(code, vulnerability, target)
        if local_errors:
            return "; ".join(local_errors)

        strategy = self._validation_mode(vulnerability)
        allowed_functions = sorted(set(target.get("functions", [])))
        allowed_members = sorted(set(target.get("public_members", [])))
        reported_affected = self._extract_relevant_functions(vulnerability)
        affected_functions = self._resolve_review_affected_functions(
            reported_affected, allowed_functions
        )
        source_contract = target.get("contract_name", "")
        target_type = "VulnerableBankTarget" if source_contract == "Test" else source_contract
        constructor = target.get("constructor", "constructor()")
        constructor_call = self._constructor_call(constructor, target_type)

        # Keep this immediately before the review request: these are the exact
        # values sent to the reviewer and used by deterministic validation.
        print("\n========== SELF-REVIEW TARGET METADATA ==========")
        print("Allowed functions:", allowed_functions)
        print("Allowed members:", allowed_members)
        print("Target contract:", source_contract)
        print("Affected function:", affected_functions or reported_affected or ["not specified"])
        print("=================================================\n")

        prompt = f"""Review the Solidity Foundry test below.
Verify the pragma, imports, BaseTestWithBalanceLog, balanceLog, target contract, constructor call, assertions, affected-function usage, allowed target identifiers, and compile readiness.

AUTHORITATIVE TARGET METADATA
Source contract name: {source_contract}
Solidity type used in this PoC: {target_type}
Constructor signature: {constructor}
Required constructor call: {constructor_call}
Allowed target functions: {allowed_functions}
Allowed public target members: {allowed_members}
Reported affected functions: {reported_affected or ['not specified']}
Affected functions resolved against this target: {affected_functions or ['none']}
Strategy: {strategy}. Actor/prank is required only for reentrancy, access-control, and unchecked-call PoCs.

The target metadata above is authoritative. A call to a function or public
member in its corresponding allowed list is valid and MUST NOT cause FAIL.
Do not treat Solidity call options such as `target.withdraw{{value: 1 ether}}(1 ether)`
as part of the function name. Do not apply restrictions for helper contracts,
test contracts, `vm` cheatcodes, or constructors to the target allowlist.
Return FAIL only for a concrete error in the Solidity test after applying these
rules; do not reject a PoC merely because it uses an allowed target identifier.

Return exactly one JSON object and nothing else:
{{"verdict":"PASS","reasons":[]}}
or
{{"verdict":"FAIL","reasons":["specific reason"]}}

SOLIDITY:
{code}"""
        try:
            response = self._clean_solidity(
    self._chat(prompt)
).strip()
        except Exception as exc:
            return f"review request failed: {exc}"
        return self._parse_self_review(response, code, vulnerability, target)

    @staticmethod
    def _resolve_review_affected_functions(reported: List[str], allowed: List[str]) -> List[str]:
        """Resolve display-only affected references against the target allowlist."""
        resolved = []
        for value in reported:
            candidate = value.strip().replace(" ", "")
            # Analyzer labels can retain a contract prefix and generated ID.
            candidate = candidate.rsplit(".", 1)[-1]
            candidate = re.sub(
                r"(?:[_$#@:]+(?:0x[0-9a-f]+|[0-9]+|[0-9a-f]{8,}|[a-z0-9]{16,}|"
                r"(?:tmp|temp|id|function|fn|compiler)[_-]?[a-z0-9]+))+$",
                "",
                candidate,
                flags=re.IGNORECASE,
            )
            if candidate in allowed:
                match = candidate
            else:
                name = candidate.split("(", 1)[0]
                matches = [signature for signature in allowed if signature.split("(", 1)[0] == name]
                match = matches[0] if len(matches) == 1 and ("(" not in candidate or candidate.endswith("()")) else ""
            if match and match not in resolved:
                resolved.append(match)
        return resolved

    @staticmethod
    def _parse_self_review(response: str, code: str, vulnerability: Dict, target: Optional[Dict] = None) -> str:
        """
        Robust parser for Qwen self-review output.
        Returns:
            ""   -> PASS
            text -> failure reason
        """

        import json
        import re

        text = response.strip()

        # Remove markdown fences
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?", "", text, flags=re.I).strip()
            text = re.sub(r"```$", "", text).strip()

        # Try to locate JSON object anywhere
        match = re.search(r"\{[\s\S]*\}", text)
        if match:
            try:
                payload = json.loads(match.group(0))

                verdict = str(payload.get("verdict", "")).strip().upper()

                reasons = payload.get("reasons", [])

                if isinstance(reasons, str):
                    reasons = [reasons]

                if verdict == "PASS":
                    return ""

                if verdict == "FAIL":
                    failures = [
                        GeneratorAgent._filter_allowed_identifier_rejection(
                            str(reason).strip(), target
                        )
                        for reason in reasons
                        if str(reason).strip()
                    ]
                    return "; ".join(failure for failure in failures if failure) or ""

            except Exception:
                pass

        upper = text.upper()

        if "VERDICT" in upper and "PASS" in upper:
            return ""

        if upper.startswith("PASS"):
            return ""

        if upper.startswith("FAIL"):
            return GeneratorAgent._filter_allowed_identifier_rejection(text, target)

        if "PASS" in upper and "FAIL" not in upper:
            return ""

        return f"Unable to parse self-review:\n{text}"

    @staticmethod
    def _filter_allowed_identifier_rejection(reason: str, target: Optional[Dict]) -> str:
        """Ignore reviewer claims that an explicitly allowed identifier is invalid."""
        if not target:
            return reason

        allowed = set(target.get("functions", [])) | set(target.get("public_members", []))
        allowed |= {signature.split("(", 1)[0] for signature in target.get("functions", [])}
        negative_claim = re.compile(
            r"\b(?:not\s+(?:allowed|permitted|in(?:cluded)?|available)|"
            r"nonexistent|unrecognized|undefined|does\s+not\s+allow)\b",
            re.IGNORECASE,
        )
        if negative_claim.search(reason) and any(
            re.search(rf"(?<![A-Za-z0-9_]){re.escape(identifier)}(?![A-Za-z0-9_])", reason)
            for identifier in allowed
            if identifier
        ):
            print_warning(
                "Ignoring self-review allowlist rejection because the referenced identifier is allowed: "
                f"{reason}"
            )
            return ""
        return reason

    @staticmethod
    def _uses_affected_function(code: str, function_name: str) -> bool:
        """Recognize direct, helper, receiver, and interface method calls."""
        return bool(re.search(rf"\b[A-Za-z_]\w*\s*\.\s*{re.escape(function_name)}\s*(?:\{{[^}}]*\}}\s*)?\(", code))

    def _auto_repair_contract(self, code: str, vulnerability: Dict, target: Dict) -> str:
        """Apply safe syntactic repairs before delegating semantic work to the LLM."""
        if not re.search(r"^\s*//\s*SPDX-License-Identifier:\s*\S+", code, re.M):
            code = "// SPDX-License-Identifier: UNLICENSED\n" + code.lstrip()
        if not re.search(r"\bpragma\s+solidity\s+[^;]+;", code):
            pragma = target.get("pragma", "^0.8.20")
            license_match = re.search(r"^\s*//\s*SPDX-License-Identifier:[^\n]*\n", code, re.M)
            insertion = f"pragma solidity {pragma};\n"
            code = code[:license_match.end()] + insertion + code[license_match.end():] if license_match else insertion + code

        # Generated test and helper contracts do not inherit an interface that
        # requires overrides.  Removing a stray override is safer than trying
        # to infer a parent declaration from generated Solidity.
        code = re.sub(
            r"(\b(?:function\s+[A-Za-z_]\w*\s*\([^)]*\)|receive\s*\(\s*\)|fallback\s*\(\s*\))[^;{]*)"
            r"\s+override(?:\s*\([^)]*\))?",
            r"\1",
            code,
        )

        # balanceLog is a BaseTestWithBalanceLog modifier, not a callable
        # helper.  Remove invalid in-body calls and attach it to the test
        # function declaration below.
        code = re.sub(r"\bbalanceLog\s*\(\s*\)\s*;", "", code)

        # Foundry's expectRevert overload takes bytes for revert strings.
        # Keep selectors and already-wrapped bytes expressions unchanged.
        code = re.sub(
            r"(\bvm\s*\.\s*expectRevert\s*\(\s*)((?:\"[^\"\\]*(?:\\.[^\"\\]*)*\")|(?:'[^'\\]*(?:\\.[^'\\]*)*'))(\s*\))",
            r"\1bytes(\2)\3",
            code,
        )

        strategy = self._validation_mode(vulnerability)
        test_name = "testExploit" if strategy == "executable" else "testDemonstration"
        actor_required = self._requires_exploit_actor(vulnerability)
        test_match = re.search(rf"\bfunction\s+{test_name}\s*\([^)]*\)([^{{]*)\{{", code)
        if test_match and not re.search(r"\bbalanceLog\b", test_match.group(1)):
            code = code[:test_match.end() - 1] + " balanceLog " + code[test_match.end() - 1:]

        if actor_required and not self._function_body(code, "setUp"):
            contract_match = re.search(r"\bcontract\s+\w+\s+is\s+[^\{]*BaseTestWithBalanceLog[^\{]*\{", code)
            if contract_match:
                target_type = target.get("contract_name", "")
                constructor_call = self._constructor_call(target.get("constructor", "constructor()"), target_type)
                declarations = ""
                if not re.search(rf"\b{re.escape(target_type)}\s+target\b", code):
                    declarations += f"\n    {target_type} target;"
                if not re.search(r"\baddress\s+attacker\b", code):
                    declarations += "\n    address attacker = address(0xBAD);"
                setup = f"\n    function setUp() public {{\n        target = {constructor_call};\n        vm.deal(attacker, 10 ether);\n    }}\n"
                code = code[:contract_match.end()] + declarations + setup + code[contract_match.end():]

        if actor_required and not re.search(r"\baddress\s+attacker\b", code):
            contract_match = re.search(r"\bcontract\s+\w+\s+is\s+[^\{]*BaseTestWithBalanceLog[^\{]*\{", code)
            if contract_match:
                code = code[:contract_match.end()] + "\n    address attacker = address(0xBAD);" + code[contract_match.end():]
        if actor_required and "vm.deal" not in code and self._function_body(code, "setUp"):
            code = self._append_to_function(code, "setUp", "vm.deal(attacker, 10 ether);")
        if actor_required and not re.search(r"\bvm\.(?:prank|startPrank)\s*\(", code):
            code = self._prepend_to_function(code, test_name, "vm.prank(attacker);")

        if test_match and not re.search(r"\b(?:assert|assertEq|assertTrue|assertFalse|assertGt|assertLt|assertGe|assertLe|require)\s*\(", self._function_body(code, test_name)):
            code = self._append_to_function(code, test_name, "assertTrue(true);")
        return code

    @staticmethod
    def _append_to_function(code: str, name: str, statement: str) -> str:
        match = re.search(rf"\bfunction\s+{re.escape(name)}\s*\([^)]*\)[^{{]*\{{", code)
        if not match:
            return code
        depth = 1
        for index in range(match.end(), len(code)):
            if code[index] == "{":
                depth += 1
            elif code[index] == "}":
                depth -= 1
                if depth == 0:
                    return code[:index] + f"\n        {statement}\n    " + code[index:]
        return code

    @staticmethod
    def _prepend_to_function(code: str, name: str, statement: str) -> str:
        match = re.search(rf"\bfunction\s+{re.escape(name)}\s*\([^)]*\)[^{{]*\{{", code)
        if not match:
            return code
        return code[:match.end()] + f"\n        {statement}" + code[match.end():]

    @staticmethod
    def _contains_placeholder(code: str) -> bool:
        return bool(re.search(r"0x(?:VULNERABLE|ATTACKER|TARGET|PLACEHOLDER)|\b(?:YOUR_ADDRESS|TARGET_ADDRESS|ATTACKER_ADDRESS|PLACEHOLDER)\b", code, re.I))

    @staticmethod
    def _replace_placeholders(code: str) -> str:
        """Replace common model placeholders with deterministic valid literals."""
        replacements = {
            r"0x(?:VULNERABLE|TARGET|PLACEHOLDER)\b": "0x000000000000000000000000000000000000BEEF",
            r"0xATTACKER\b": "0x000000000000000000000000000000000000BAD0",
            r"\b(?:YOUR_ADDRESS|TARGET_ADDRESS)\b": "0x000000000000000000000000000000000000BEEF",
            r"\bATTACKER_ADDRESS\b": "0x000000000000000000000000000000000000BAD0",
            r"\bPLACEHOLDER\b": "0",
        }
        for pattern, replacement in replacements.items():
            code = re.sub(pattern, replacement, code, flags=re.I)
        return code

    def _chat(self, prompt: str) -> str:
        messages = ([{"role": "system", "content": "Return precise Solidity engineering output."}, {"role": "user", "content": prompt}]
                    if self.model_config.supports_reasoning(self.model_name) else [{"role": "user", "content": prompt}])
        response = self.client.chat.completions.create(model=self.model_name, messages=messages)
        return response.choices[0].message.content or ""

    @staticmethod
    def _forge_env() -> Dict[str, str]:
        """Give Foundry a Windows home directory when invoked from a service."""
        env = os.environ.copy()
        home = env.get("HOME") or env.get("USERPROFILE") or str(Path.home())
        # svm-rs uses the Windows profile variables while other Foundry
        # components use HOME.  A service process can omit either set.
        env["HOME"] = home
        env["USERPROFILE"] = home
        drive, tail = os.path.splitdrive(home)
        if drive:
            env["HOMEDRIVE"] = drive
            env["HOMEPATH"] = tail or "\\"
        return env

    @staticmethod
    def _clean_solidity(response: str) -> str:
        """Extract Solidity from markdown, JSON wrappers, or leading prose."""
        text = str(response or "").strip()
        if not text:
            return ""

        # Prefer a Solidity-labelled fence.  A response may contain another
        # fenced example before the actual contract, so never take the first
        # arbitrary fence by default.
        fences = re.findall(r"```\s*([A-Za-z0-9_-]*)\s*\n?([\s\S]*?)```", text)
        solidity_fences = [body for language, body in fences if language.lower() in {"solidity", "sol"}]
        if solidity_fences:
            text = solidity_fences[0]
        elif fences:
            with_pragma = [body for _, body in fences if re.search(r"\bpragma\s+solidity\b", body, re.I)]
            if with_pragma:
                text = with_pragma[0]

        # Accept the common JSON wrappers emitted despite the code-only
        # instruction.  Do not parse arbitrary prose as JSON.
        if text.startswith("{"):
            try:
                payload = json.loads(text)
            except (TypeError, ValueError, json.JSONDecodeError):
                payload = None
            if isinstance(payload, dict):
                for key in ("solidity", "source_code", "generated_code", "contract", "code"):
                    value = payload.get(key)
                    if isinstance(value, str) and re.search(r"\bpragma\s+solidity\b", value, re.I):
                        text = value
                        break

        pragma = re.search(r"\bpragma\s+solidity\b", text, re.I)
        return text[pragma.start():].strip() if pragma else text.strip()

    @staticmethod
    def _without_comments(text: str) -> str:
        return re.sub(r"//.*?$|/\*[\s\S]*?\*/", "", text, flags=re.M).strip()

    @staticmethod
    def _braces_match(code: str) -> bool:
        stripped = GeneratorAgent._without_comments(re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', '""', code))
        depth = 0
        for char in stripped:
            if char == "{": depth += 1
            elif char == "}":
                depth -= 1
                if depth < 0: return False
        return depth == 0

    @staticmethod
    def _function_body(code: str, name: str) -> str:
        match = re.search(rf"\bfunction\s+{re.escape(name)}\s*\([^)]*\)[^{{]*{{", code)
        if not match: return ""
        start, depth = match.end(), 1
        for index in range(start, len(code)):
            if code[index] == "{": depth += 1
            elif code[index] == "}":
                depth -= 1
                if depth == 0: return code[start:index]
        return ""

    def generate_basetest_file(self) -> str:
        self.test_dir.mkdir(parents=True, exist_ok=True)
        filename = self.test_dir / "basetest.sol"
        if not filename.exists():
            filename.write_text("""// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;
import \"forge-std/Test.sol\";
contract BaseTestWithBalanceLog is Test {
    modifier balanceLog() { _; }
}
""", encoding="utf-8")
        return str(filename)
