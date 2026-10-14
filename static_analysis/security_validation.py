"""Helpers for comparing static-analysis findings across contract revisions."""

from collections import Counter
import re
from typing import Any, Dict, Iterable, List, Mapping, Tuple


_TARGET_CHECKS = {
    "reentrancy": ("reentrancy-",),
    "uncheckedlowlevelcalls": (
        "unchecked-lowlevel",
        "unchecked-send",
        "unchecked-transfer",
        "unchecked-return-values",
    ),
    "uncheckedlowlevelcall": (
        "unchecked-lowlevel",
        "unchecked-send",
        "unchecked-transfer",
        "unchecked-return-values",
    ),
    "accesscontrol": (
        "arbitrary-send-eth",
        "suicidal",
        "tx-origin",
        "controlled-delegatecall",
        "unprotected-upgradeable",
    ),
    "weakrandomness": ("bad-prng",),
    "timestampdependence": ("block-timestamp",),
}

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}


def _flatten_findings(results: Any) -> List[Dict[str, Any]]:
    findings = []

    def visit(value):
        if isinstance(value, Mapping):
            if isinstance(value.get("check"), str):
                findings.append(dict(value))
                return
            for child in value.values():
                visit(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                visit(child)

    visit(results)
    return findings


def _function_signatures(value: Any) -> List[str]:
    signatures = set()

    def visit(element):
        if isinstance(element, Mapping):
            if str(element.get("type", "")).lower() == "function":
                fields = element.get("type_specific_fields")
                name = fields.get("signature") if isinstance(fields, Mapping) else None
                name = name or element.get("name")
                if isinstance(name, str) and name:
                    signatures.add(name.rsplit(".", 1)[-1].strip().lower())
            for child in element.values():
                visit(child)
        elif isinstance(element, (list, tuple)):
            for child in element:
                visit(child)

    visit(value)
    return sorted(signatures)


def _finding_identity(finding: Mapping[str, Any]) -> Tuple[str, Tuple[str, ...], str]:
    check = str(finding.get("check", "")).strip().lower()
    functions = tuple(_function_signatures(finding.get("elements", [])))
    if functions:
        return check, functions, ""

    description = str(finding.get("description", "")).lower()
    description = re.sub(r"\b[\w./-]+#l\d+(?:-l?\d+)?\b", "", description)
    description = re.sub(r"\bline\s+\d+(?:\s*[-–]\s*\d+)?\b", "", description)
    description = re.sub(r"\s+", " ", description).strip()
    return check, (), description


def _is_target_finding(finding: Mapping[str, Any], vulnerabilities: Iterable[Any]) -> bool:
    check = str(finding.get("check", "")).strip().lower()
    for vulnerability in vulnerabilities:
        if isinstance(vulnerability, Mapping):
            label = str(vulnerability.get("vulnerability_type", "")).lower()
        else:
            label = str(vulnerability).lower()
        normalized = re.sub(r"[^a-z0-9]", "", label)
        prefixes = next(
            (checks for category, checks in _TARGET_CHECKS.items() if normalized.startswith(category)),
            (),
        )
        if any(check.startswith(prefix) for prefix in prefixes):
            return True
    return False


def _finding_summary(finding: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "check": finding.get("check", "unknown"),
        "impact": finding.get("impact", "Unknown"),
        "confidence": finding.get("confidence", "Unknown"),
        "functions": _function_signatures(finding.get("elements", [])),
        "description": str(finding.get("description", "")).strip(),
    }


def compare_detector_findings(
    original_results: Any,
    generated_results: Any,
    target_vulnerabilities: Iterable[Any],
) -> Dict[str, Any]:
    """Compare detector output and decide whether a generated revision is acceptable."""
    original = _flatten_findings(original_results)
    generated = _flatten_findings(generated_results)
    original_counts = Counter(_finding_identity(item) for item in original)
    generated_counts = Counter(_finding_identity(item) for item in generated)
    original_severity = {}
    for finding in original:
        identity = _finding_identity(finding)
        severity = _SEVERITY_ORDER.get(str(finding.get("impact", "")).lower(), -1)
        original_severity[identity] = max(original_severity.get(identity, -1), severity)

    resolved = []
    remaining = []
    introduced = []
    for identity, count in (original_counts - generated_counts).items():
        finding = next(item for item in original if _finding_identity(item) == identity)
        resolved.extend([_finding_summary(finding)] * count)
    for identity, count in (generated_counts - original_counts).items():
        finding = next(item for item in generated if _finding_identity(item) == identity)
        introduced.extend([_finding_summary(finding)] * count)
    for finding in generated:
        if _is_target_finding(finding, target_vulnerabilities):
            remaining.append(_finding_summary(finding))

    new_critical_or_high = []
    for finding in generated:
        identity = _finding_identity(finding)
        severity = _SEVERITY_ORDER.get(str(finding.get("impact", "")).lower(), -1)
        if severity >= _SEVERITY_ORDER["high"] and severity > original_severity.get(identity, -1):
            new_critical_or_high.append(_finding_summary(finding))
    passed = not remaining and not new_critical_or_high
    return {
        "passed": passed,
        "original_finding_count": len(original),
        "generated_finding_count": len(generated),
        "resolved_findings": resolved,
        "remaining_target_findings": remaining,
        "introduced_findings": introduced,
        "blocking_findings": remaining + new_critical_or_high,
    }
