"""Reliable Foundry execution and compiler-diagnostic repair loop."""
import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Dict, Optional, Tuple

from ..config import ModelConfig
from ..ollama_client import OllamaClient
from utils.print_utils import print_warning
from .generator import GeneratorAgent


class ExploitRunner:
    def __init__(self, model_config=None):
        self.model_config = model_config or ModelConfig()
        self.model_name = self.model_config.get_model("generator")
        self.client = OllamaClient(
            base_url=self.model_config.base_url,
            model=self.model_name,
            timeout=self.model_config.ollama_request_timeout,
        )
        self.max_retries = self.model_config.poc_max_retries
        self.project_root = Path.cwd()
        self.exploit_root = self.project_root / "exploit"
        # Reuse one validator/client across all repairs; do not create one per attempt.
        self.validator = GeneratorAgent(self.model_config)

    def run_and_fix_exploit(self, poc_data: Dict, status_callback=None) -> Dict:
        def emit_status(state: str, detail: str):
            if status_callback:
                try:
                    status_callback(state, detail)
                except Exception as cb_err:
                    print_warning(f"Runner status callback error: {cb_err}")

        emit_status("PREPARING", "Preparing isolated test environment")
        path = Path(poc_data.get("exploit_file", ""))
        if not path.is_file():
            emit_status("ERROR", "Exploit file not found")
            return self._result(error=poc_data.get("generation_error", "Exploit file not found"), runner_state="ERROR")

        diagnostics, output = [], ""
        previous_attempt = ""
        last_compile = {"compiled": False, "compile_error": "", "stdout": "", "stderr": "", "compile_time": 0.0}
        last_execution = {"executed": False, "success": False, "runtime_error": "", "stdout": "", "stderr": "", "execution_time": 0.0, "gas_used": None, "execution_trace": ""}
        
        actual_retries_attempted = 0
        final_state = "FAILED"

        for attempt in range(self.max_retries + 1):
            if attempt > 0:
                actual_retries_attempted = attempt

            emit_status("COMPILING", f"Compiling generated PoC (attempt {attempt + 1})")
            current = path.read_text(encoding="utf-8")
            last_compile = self.validator.compile_candidate(current, attempt=attempt)
            
            if last_compile["compiled"]:
                emit_status("EXECUTING", f"Executing exploit test (attempt {attempt + 1})")
                last_execution = self._execute_test(path, attempt, current)
                output = last_execution["output"]
                diagnostic = self._diagnose(output)
                diagnostics.append(diagnostic)

                if last_execution.get("is_timeout"):
                    final_state = "TIMEOUT"
                    emit_status("TIMEOUT", "PoC execution timed out")
                    result = self._result(path, actual_retries_attempted, diagnostics, last_compile, last_execution, runner_state="TIMEOUT")
                    self._cleanup_job_workspace(path)
                    return result

                emit_status("VALIDATING", f"Validating exploit result (attempt {attempt + 1})")
                if last_execution["success"]:
                    final_state = "PASSED"
                    detail = f"PoC validated successfully on attempt {attempt + 1}"
                    emit_status("PASSED", detail)
                    result = self._result(path, actual_retries_attempted, diagnostics, last_compile, last_execution, runner_state="PASSED")
                    self._cleanup_job_workspace(path)
                    return result
                else:
                    final_state = "FAILED"
            else:
                final_state = "FAILED"
                output = last_compile["output"]
                diagnostic = self._diagnose(output)
                diagnostics.append(diagnostic)

            if attempt == self.max_retries:
                break

            current = path.read_text(encoding="utf-8")
            candidate = self._fix_test_code(current, output, diagnostic, previous_attempt, poc_data.get("target_contract", {}))
            previous_attempt = current
            if not candidate:
                continue
            candidate = GeneratorAgent._clean_solidity(candidate)
            self._write_repair_artifacts(path, candidate, output, attempt)
            target = poc_data.get("target_contract", {"filename": "VulnerableContract.sol", "contract_name": "VulnerableContract", "functions": []})
            errors = self.validator.validate_contract(candidate, {}, target)
            if errors:
                diagnostics.append({"categories": ["RepairValidationError"], "output": "; ".join(errors)})
                continue
            path.write_text(candidate, encoding="utf-8")

        emit_status("FAILED", f"PoC failed after {actual_retries_attempted + 1} attempts" if actual_retries_attempted > 0 else "PoC execution failed")
        result = self._result(path, actual_retries_attempted, diagnostics, last_compile, last_execution, runner_state=final_state)
        self._cleanup_job_workspace(path)
        return result

    def _execute_test(self, path: Path, attempt: int, code: str) -> Dict:
        execution_root = self.exploit_root / ".poc_execution" / uuid.uuid4().hex
        started = time.perf_counter()
        stdout = stderr = ""
        returncode = None
        is_timeout = False
        try:
            (execution_root / "test").mkdir(parents=True)
            self.validator._copy_candidate_sources(code, execution_root / "src")
            lib = self.exploit_root / "lib"
            if lib.exists():
                shutil.copytree(lib, execution_root / "lib")
            self.validator.generate_basetest_file()
            shutil.copy2(self.validator.test_dir / "basetest.sol", execution_root / "test" / "basetest.sol")
            (execution_root / "test" / "Candidate.t.sol").write_text(code, encoding="utf-8")
            (execution_root / "foundry.toml").write_text(
                '[profile.default]\nsrc = "src"\ntest = "test"\nlibs = ["lib"]\nout = "out"\ncache_path = "cache"\n',
                encoding="utf-8",
            )
            command = ["forge", "test", "-vv", "--match-path", "./test/Candidate.t.sol"]
            solc = shutil.which("solc")
            if solc:
                command.extend(["--use", solc])
            result = subprocess.run(
                command,
                cwd=execution_root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.model_config.forge_test_timeout,
                env=GeneratorAgent._forge_env(),
            )
            stdout, stderr, returncode = result.stdout or "", result.stderr or "", result.returncode
        except subprocess.TimeoutExpired as exc:
            is_timeout = True
            stderr = f"Execution timed out (Forge test exceeded {self.model_config.forge_test_timeout} seconds)"
            stdout = exc.stdout or "" if isinstance(exc.stdout, str) else ""
        except OSError as exc:
            stderr = f"Unable to execute forge test: {exc}"
        finally:
            shutil.rmtree(execution_root, ignore_errors=True)
            try:
                execution_root.parent.rmdir()
            except OSError:
                pass
        execution_time = time.perf_counter() - started
        output = stdout + ("\n" if stdout and stderr else "") + stderr
        # Foundry's return code is stable across output-format changes.
        success = (returncode == 0) and not is_timeout
        self._write_execution_artifacts(path, code, stdout, stderr, attempt)
        return {
            "executed": returncode is not None or is_timeout,
            "success": success,
            "is_timeout": is_timeout,
            "runtime_error": "" if success else (stderr or stdout or "Forge execution failed with no diagnostic."),
            "stdout": stdout, "stderr": stderr, "output": output,
            "execution_time": execution_time,
            "gas_used": self._extract_gas(output),
            "execution_trace": output,
            "failure_reason": "TIMEOUT" if is_timeout else ("" if success else self._failure_reason(output, returncode)),
        }

    def _cleanup_job_workspace(self, path: Path) -> None:
        """Delete only generated per-job PoCs after execution completes."""
        workspace_root = (self.exploit_root / "tmp").resolve()
        try:
            resolved = path.resolve()
            if not resolved.is_relative_to(workspace_root):
                return
            job_dir = resolved.parent
            if job_dir.parent != workspace_root:
                return
            shutil.rmtree(job_dir)
            print(f"[Runner] Removed isolated Forge workspace: {job_dir}")
        except OSError as exc:
            print_warning(f"Unable to remove isolated Forge workspace for {path}: {exc}")

    def _result(self, path: Optional[Path] = None, retries: int = 0, diagnostics=None,
                compile_result=None, execution_result=None, error: str = "", runner_state: str = "FAILED") -> Dict:
        compile_result = compile_result or {"compiled": False, "compile_error": error, "stdout": "", "stderr": "", "compile_time": 0.0}
        execution_result = execution_result or {"executed": False, "success": False, "runtime_error": error, "stdout": "", "stderr": "", "output": "", "execution_time": 0.0, "gas_used": None, "execution_trace": ""}
        success = bool(compile_result["compiled"] and execution_result["success"])
        return {
            "success": success,
            "runner_state": runner_state,
            "compiled": bool(compile_result["compiled"]),
            "executed": bool(execution_result["executed"]),
            "is_timeout": bool(execution_result.get("is_timeout", False)),
            "compile_error": compile_result.get("compile_error", ""),
            "runtime_error": execution_result.get("runtime_error", ""),
            "failure_reason": execution_result.get("failure_reason", "") or ("CompilationFailure" if not compile_result["compiled"] else ""),
            "stdout": execution_result.get("stdout", "") or compile_result.get("stdout", ""),
            "stderr": execution_result.get("stderr", "") or compile_result.get("stderr", ""),
            "output": execution_result.get("output", "") or compile_result.get("output", ""),
            "error": error or execution_result.get("runtime_error", "") or compile_result.get("compile_error", ""),
            "file_path": str(path) if path else "",
            "retries": retries,
            "diagnostics": diagnostics or [],
            "compile_time": compile_result.get("compile_time", 0.0),
            "execution_time": execution_result.get("execution_time", 0.0),
            "gas_used": execution_result.get("gas_used"),
            "execution_trace": execution_result.get("execution_trace", "")
        }

    def _write_execution_artifacts(self, path: Path, code: str, stdout: str, stderr: str, attempt: int) -> None:
        reports = self.project_root / "reports"
        reports.mkdir(exist_ok=True)
        prefix = reports / f"runner_{path.stem}_{int(time.time() * 1000)}_{uuid.uuid4().hex}_attempt{attempt}_execute"
        prefix.with_suffix(".sol").write_text(code, encoding="utf-8")
        prefix.with_suffix(".stdout.log").write_text(stdout, encoding="utf-8")
        prefix.with_suffix(".stderr.log").write_text(stderr, encoding="utf-8")
        # -vv writes Foundry's runtime trace to stdout; keeping a separate
        # artifact makes trace discovery independent of Forge formatting.
        prefix.with_suffix(".trace.log").write_text(stdout + ("\n" if stdout and stderr else "") + stderr, encoding="utf-8")

    def _write_repair_artifacts(self, path: Path, code: str, diagnostic: str, attempt: int) -> None:
        reports = self.project_root / "reports"
        reports.mkdir(exist_ok=True)
        prefix = reports / f"runner_{path.stem}_{int(time.time() * 1000)}_{uuid.uuid4().hex}_attempt{attempt}_repair"
        prefix.with_suffix(".sol").write_text(code, encoding="utf-8")
        prefix.with_suffix(".diagnostic.log").write_text(diagnostic, encoding="utf-8")

    @staticmethod
    def _extract_gas(output: str) -> Optional[int]:
        match = re.search(r"\bgas:\s*(\d+)", output, re.I)
        return int(match.group(1)) if match else None

    def _write_repair_log(self, path: Path, attempt: int, stage: str, output: str) -> None:
        reports = self.project_root / "reports"
        reports.mkdir(exist_ok=True)
        (reports / f"repair_{path.stem}_{int(time.time() * 1000)}_attempt{attempt}_{stage}.log").write_text(output, encoding="utf-8")

    @staticmethod
    def _diagnose(output: str) -> Dict:
        categories = [label for label, pattern in {
            "ParserError": r"ParserError", "TypeError": r"TypeError", "DeclarationError": r"DeclarationError",
            "CompilerError": r"(?:CompilerError|Error \(\d+\))", "Revert": r"\brevert(?:ed)?\b",
            "RuntimeFailure": r"(?:runtime error|Execution failed)", "OutOfGas": r"out of gas",
            "Panic": r"\bPanic\b", "MissingImport": r"(?:not found|No such file|failed to resolve import)",
            "MissingContract": r"(?:Identifier not found|not a contract)", "FailedAssertion": r"(?:AssertionFailed|assert(?:Eq|True|False)|FAIL)",
        }.items() if re.search(pattern, output, re.I)]
        return {"categories": categories or ["UnknownFailure"], "output": output}

    @staticmethod
    def _failure_reason(output: str, returncode: Optional[int]) -> str:
        diagnostic = ExploitRunner._diagnose(output)
        for category in ("FailedAssertion", "Panic", "OutOfGas", "Revert", "RuntimeFailure"):
            if category in diagnostic["categories"]:
                return category
        return "ForgeExecutionError" if returncode is not None else "ForgeLaunchError"

    def _fix_test_code(self, current: str, output: str, diagnostic: Dict, previous: str, target: Dict) -> Optional[str]:
        function_map = ", ".join(target.get("functions", [])) or "none"
        public_members = ", ".join(target.get("public_members", [])) or "none"
        prompt = f"""You repair compact Solidity Foundry tests for qwen2.5-coder:7b. Rewrite this complete test and return only Solidity.
Preserve the exploit/demonstration intent and address every diagnostic. The target permits only these callable signatures: {function_map}. Its public getters are: {public_members}. Never invent target functions, variables, imports, pragma, or constructor arguments.

CURRENT SOLIDITY:
{current}

COMPLETE FORGE OUTPUT:
{output}

DIAGNOSTICS: {diagnostic}
PREVIOUS ATTEMPT: {previous or 'none'}
"""
        try:
            messages = [{"role": "user", "content": prompt}]
            response = self.client.chat.completions.create(model=self.model_name, messages=messages)
            return response.choices[0].message.content or None
        except Exception as exc:
            print_warning(f"Unable to request PoC repair: {exc}")
            return None
