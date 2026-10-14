"""Re-run security and interface checks on generated Solidity candidates."""

import json
import os
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .parse_contract import analyze_contract
from .security_validation import compare_detector_findings, has_target_detector_finding


def _compiler_for(source_path):
    configured = os.environ.get("SOLC_BINARY")
    if configured:
        return configured
    match = re.search(
        r"\bpragma\s+solidity\s+[^;]*?0\.(\d+)\.",
        Path(source_path).read_text(encoding="utf-8", errors="replace"),
    )
    if match and int(match.group(1)) < 5:
        candidates = [
            os.environ.get("SOLC_0_4_26"),
            r"C:\Solidity\solc-0.4.26\solc.exe",
            shutil.which("solc-0.4.26"),
        ]
        return next((item for item in candidates if item and Path(item).is_file()), None)
    return shutil.which("solc")


def _compile_abi(source_path):
    compiler = _compiler_for(source_path)
    if not compiler:
        return {
            "compiled": False,
            "signatures": [],
            "error": "No compatible solc executable was found for ABI compilation.",
        }
    source_path = Path(source_path).resolve()
    command = [compiler]
    if compiler == shutil.which("solc") and compiler:
        command.extend(["--base-path", str(source_path.parent)])
    command.extend(["--combined-json", "abi", str(source_path)])
    completed = subprocess.run(
        command,
        cwd=str(source_path.parent),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if completed.returncode:
        return {
            "compiled": False,
            "signatures": [],
            "error": (completed.stderr or completed.stdout).strip(),
        }
    match = re.search(r"\{[\s\S]*\}", completed.stdout)
    if not match:
        return {
            "compiled": False,
            "signatures": [],
            "error": "solc completed without returning combined ABI JSON.",
        }
    try:
        output = json.loads(match.group(0))
    except json.JSONDecodeError as exc:
        return {
            "compiled": False,
            "signatures": [],
            "error": f"Could not parse solc ABI output: {exc}",
        }
    signatures = set()
    for contract in output.get("contracts", {}).values():
        try:
            abi = contract.get("abi", [])
            abi_items = json.loads(abi) if isinstance(abi, str) else abi
        except (TypeError, json.JSONDecodeError):
            continue
        for item in abi_items:
            if item.get("type") != "function":
                continue
            parameters = ",".join(_canonical_abi_type(arg) for arg in item.get("inputs", []))
            signatures.add(f"{item.get('name')}({parameters})")
    return {"compiled": True, "signatures": sorted(signatures), "error": ""}


def _canonical_abi_type(argument):
    abi_type = argument.get("type", "")
    if not abi_type.startswith("tuple"):
        return abi_type
    suffix = abi_type[len("tuple"):]
    components = ",".join(
        _canonical_abi_type(component)
        for component in argument.get("components", [])
    )
    return f"({components}){suffix}"


def reverify_candidate(
    original_path,
    candidate_path,
    vulnerabilities,
    original_detector_results,
):
    """Validate candidate compilation, ABI preservation, and Slither findings."""
    original_path = Path(original_path).resolve()
    candidate_path = Path(candidate_path).resolve()
    original_abi = _compile_abi(original_path)
    try:
        with _candidate_copy_near_source(candidate_path, original_path.parent) as scratch_path:
            candidate_abi = _compile_abi(scratch_path)
            compile_success = original_abi["compiled"] and candidate_abi["compiled"]
            abi_preserved = (
                compile_success
                and original_abi["signatures"] == candidate_abi["signatures"]
            )
            _, _, candidate_detectors = analyze_contract(str(scratch_path))
    except Exception as exc:
        return {
            "passed": False,
            "Vo": int(has_target_detector_finding(original_detector_results, vulnerabilities)),
            "Vp": None,
            "security_fix": False,
            "functional_preservation": {
                "compiled": False,
                "abi_preserved": False,
                "passed": False,
                "original_compile_error": original_abi["error"],
                "candidate_compile_error": str(exc),
                "error": str(exc),
            },
            "original_detector_results": original_detector_results,
            "candidate_detector_results": [],
            "comparison": None,
        }

    compile_success = original_abi["compiled"] and candidate_abi["compiled"]
    abi_preserved = (
        compile_success
        and original_abi["signatures"] == candidate_abi["signatures"]
    )
    comparison = compare_detector_findings(
        original_detector_results, candidate_detectors, vulnerabilities
    )
    original_vulnerabilities_detected = has_target_detector_finding(
        original_detector_results, vulnerabilities
    )
    patched_vulnerabilities_remain = bool(
        comparison["remaining_target_findings"]
    )
    no_new_blocking_findings = not comparison["blocking_findings"]
    security_fix = (
        original_vulnerabilities_detected
        and not patched_vulnerabilities_remain
        and no_new_blocking_findings
    )
    functional_preservation = {
        "compiled": compile_success,
        "abi_preserved": abi_preserved,
        "passed": bool(compile_success and abi_preserved),
        "original_signatures": original_abi["signatures"],
        "candidate_signatures": candidate_abi["signatures"],
        "original_compile_error": original_abi["error"],
        "candidate_compile_error": candidate_abi["error"],
    }
    return {
        "passed": bool(security_fix and functional_preservation["passed"]),
        "Vo": int(original_vulnerabilities_detected),
        "Vp": int(patched_vulnerabilities_remain),
        "security_fix": security_fix,
        "functional_preservation": functional_preservation,
        "original_detector_results": original_detector_results,
        "candidate_detector_results": candidate_detectors,
        "comparison": comparison,
    }


@contextmanager
def _candidate_copy_near_source(candidate_path, source_directory):
    """Keep relative Solidity imports resolving as they did for the original."""
    with tempfile.NamedTemporaryFile(
        mode="wb",
        suffix=".sol",
        prefix=".smartaudit_candidate_",
        dir=source_directory,
        delete=False,
    ) as temp_file:
        scratch_path = Path(temp_file.name)
    try:
        shutil.copyfile(candidate_path, scratch_path)
        yield scratch_path
    finally:
        scratch_path.unlink(missing_ok=True)
