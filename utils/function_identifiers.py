"""Canonical Solidity function identifiers shared by analysis and PoC stages."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Set


def canonical_function_id(name: str, parameters: Iterable[Any] = ()) -> str:
    """Return the ABI-style identifier used throughout this application.

    The contract name is deliberately not included: a finding is evaluated
    against one analyzed target at a time, while `name(type,...)` preserves
    overload information and remains directly usable in Solidity test code.
    """
    types: List[str] = []
    for parameter in parameters:
        if isinstance(parameter, (tuple, list)):
            types.append(str(parameter[0]))
        elif isinstance(parameter, dict):
            types.append(str(parameter.get("type", "")))
        else:
            types.append(str(parameter))
    return f"{name}({','.join(types)})"


def known_function_ids(function_details: Iterable[Dict[str, Any]]) -> Set[str]:
    return {
        detail["function_id"]
        for detail in function_details
        if detail.get("function_id") and detail.get("function") not in {"constructor", "fallback", "receive"}
    }


def normalize_affected_functions(values: Iterable[Any], allowed: Set[str]) -> List[str]:
    """Normalize common LLM function references to one unambiguous known ID.

    Bare names are accepted only when the analyzed contract has one overload
    with that name, which preserves hallucination protection while accepting
    forms such as ``Contract.withdraw`` and ``withdraw()``.
    """
    normalized: List[str] = []
    for value in values or []:
        candidate = str(value).strip()
        if not candidate:
            continue
        if candidate in allowed:
            resolved = candidate
        else:
            short = candidate.rsplit(".", 1)[-1].replace(" ", "")
            name = short.split("(", 1)[0]
            matches = [function_id for function_id in allowed if function_id.split("(", 1)[0] == name]
            # Exact short signature wins.  Otherwise resolve name-only and
            # empty-parenthesis variants only when no overload is possible.
            if short in allowed:
                resolved = short
            elif len(matches) == 1 and ("(" not in short or short.endswith("()")):
                resolved = matches[0]
            else:
                continue
        if resolved not in normalized:
            normalized.append(resolved)
    return normalized
