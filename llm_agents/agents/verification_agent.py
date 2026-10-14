"""Cross-check LLM vulnerability candidates against independent Slither output."""

import re
from collections.abc import Mapping


_WEIGHTS = {"category": 0.4, "location": 0.3, "evidence": 0.3}
_CHECKS = {
    "reentrancy": ("reentrancy-",),
    "accesscontrol": (
        "arbitrary-send-eth",
        "suicidal",
        "tx-origin",
        "controlled-delegatecall",
        "unprotected-upgradeable",
    ),
    "dangerousselfdestruct": ("suicidal",),
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
    "badrandomness": ("bad-prng",),
    "weakrandomness": ("bad-prng",),
    "timestampdependence": ("block-timestamp",),
    "denialofservice": (
        "costly-operations-in-loop",
        "calls-in-loop",
        "msg-value-in-loop",
        "return-bomb",
    ),
    "integeroverflow": ("divide-before-multiply",),
    "arithmetic": ("divide-before-multiply",),
}
_STOP_WORDS = {
    "about", "after", "also", "and", "are", "because", "been", "before",
    "between", "can", "could", "does", "for", "from", "function", "has",
    "have", "into", "issue", "that", "the", "their", "then", "this",
    "through", "with", "would",
}


def _flatten_findings(results):
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


def _normalized(value):
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def _candidate_checks(vulnerability_type):
    category = _normalized(vulnerability_type)
    return next(
        (checks for name, checks in _CHECKS.items() if category.startswith(name)),
        (),
    )


def _functions(value):
    names = set()

    def visit(element):
        if isinstance(element, Mapping):
            if str(element.get("type", "")).lower() == "function":
                fields = element.get("type_specific_fields")
                name = fields.get("signature") if isinstance(fields, Mapping) else None
                name = name or element.get("name")
                if isinstance(name, str) and name:
                    names.add(name.rsplit(".", 1)[-1].strip().lower())
            for child in element.values():
                visit(child)
        elif isinstance(element, (list, tuple)):
            for child in element:
                visit(child)

    visit(value)
    return names


def _line_numbers(value):
    lines = set()

    def visit(element):
        if isinstance(element, Mapping):
            mapping = element.get("source_mapping")
            if isinstance(mapping, Mapping):
                mapped_lines = mapping.get("lines")
                if isinstance(mapped_lines, (list, tuple)):
                    lines.update(line for line in mapped_lines if isinstance(line, int))
                start, end = mapping.get("start_line"), mapping.get("end_line")
                if isinstance(start, int) and isinstance(end, int):
                    lines.update(range(start, end + 1))
            for child in element.values():
                visit(child)
        elif isinstance(element, (list, tuple)):
            for child in element:
                visit(child)

    visit(value)
    return lines


def _location_score(candidate, finding):
    candidate_functions = {
        str(name).strip().lower()
        for name in candidate.get("affected_functions", [])
        if name
    }
    candidate_functions.update(
        [str(candidate.get("function", "")).strip().lower()]
        if candidate.get("function")
        else []
    )
    static_functions = _functions(finding.get("elements", []))
    function_match = any(
        left == right
        or left.split("(", 1)[0].rsplit(".", 1)[-1]
        == right.split("(", 1)[0].rsplit(".", 1)[-1]
        for left in candidate_functions
        for right in static_functions
    )

    location = candidate.get("source_location") or {}
    start, end = location.get("start_line"), location.get("end_line")
    static_lines = _line_numbers(finding.get("elements", []))
    line_match = (
        isinstance(start, int)
        and isinstance(end, int)
        and any(start <= line <= end for line in static_lines)
    )
    if function_match and line_match:
        return 1.0
    if function_match or line_match:
        return 0.8
    return 0.0


def _evidence_score(candidate, finding):
    candidate_text = " ".join(
        str(candidate.get(field, ""))
        for field in ("explanation", "evidence", "reasoning")
    )
    static_text = " ".join(
        str(finding.get(field, ""))
        for field in ("check", "description", "markdown")
    )
    words = lambda text: {
        token for token in re.findall(r"[a-z][a-z0-9_]{2,}", text.lower())
        if token not in _STOP_WORDS
    }
    left, right = words(candidate_text), words(static_text)
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


class VerificationAgent:
    """Score each LLM candidate using category, location, and evidence signals."""

    def verify(self, candidates, slither_results):
        slither_findings = _flatten_findings(slither_results)
        verified = []
        for candidate in candidates:
            checks = _candidate_checks(candidate.get("vulnerability_type"))
            best = None
            for finding in slither_findings:
                check = str(finding.get("check", "")).lower()
                category_score = float(any(check.startswith(prefix) for prefix in checks))
                location_score = _location_score(candidate, finding)
                evidence_score = _evidence_score(candidate, finding)
                score = (
                    _WEIGHTS["category"] * category_score
                    + _WEIGHTS["location"] * location_score
                    + _WEIGHTS["evidence"] * evidence_score
                )
                if best is None or score > best["verification_score"]:
                    best = {
                        "category_agreement": category_score,
                        "location_agreement": location_score,
                        "evidence_agreement": evidence_score,
                        "verification_score": round(score, 4),
                        "slither_finding": {
                            "check": finding.get("check"),
                            "impact": finding.get("impact"),
                            "confidence": finding.get("confidence"),
                            "description": finding.get("description", ""),
                        },
                    }
            if best is None:
                best = {
                    "category_agreement": 0.0,
                    "location_agreement": 0.0,
                    "evidence_agreement": 0.0,
                    "verification_score": 0.0,
                    "slither_finding": None,
                }
            score = best["verification_score"]
            best["verification_status"] = (
                "Confirmed" if score >= 0.70
                else "Partially Supported" if score >= 0.40
                else "Unconfirmed"
            )
            verified.append({**candidate, **best})
        return {
            "verified_vulnerabilities": verified,
            "independent_slither_findings": [
                {
                    "check": item.get("check"),
                    "impact": item.get("impact"),
                    "confidence": item.get("confidence"),
                    "description": item.get("description", ""),
                    "functions": sorted(_functions(item.get("elements", []))),
                }
                for item in slither_findings
            ],
        }
