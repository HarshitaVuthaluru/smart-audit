# ==============================
# File: llm_agents/agents/analyzer.py
# ==============================
from typing import Dict, List
from pathlib import Path
import json
import logging
import os
import re
from utils.print_utils import print_warning, create_progress_spinner
try:
    from langchain_core.documents import Document
except ImportError:
    from langchain.schema import Document
from .project_context_llm import ProjectContextLLMAgent
from utils.function_identifiers import known_function_ids
from eth_utils import keccak

logger = logging.getLogger(__name__)


class AnalyzerAgent:
    RAG_FINAL_K = 5
    RAG_CANDIDATE_K = 20
    def __init__(self, retriever, model_config=None):
        from ..config import ModelConfig
        from ..ollama_client import OllamaClient

        self.retriever = retriever
        self.model_config = model_config or ModelConfig()
        self.model_name = self.model_config.get_model("analyzer")

        # Initialize local Ollama client
        self.client = OllamaClient(
            base_url=self.model_config.base_url,
            model=self.model_name,
            timeout=self.model_config.ollama_request_timeout
        )

        # Load vulnerability categories
        self.vuln_categories = self._load_vuln_categories()

    def _load_vuln_categories(self):
        """Load vulnerability category definitions"""
        categories_path = (
            Path(__file__).parent.parent.parent / "vulnerability_categories.json"
        )
        with open(categories_path, "r") as f:
            data = json.load(f)
        return data["categories"]

    def analyze(self, contract_info: Dict) -> Dict:
        try:
            contract_name = contract_info.get("target_contract", {}).get("name") or next(
                (detail.get("contract") for detail in contract_info.get("function_details", []) if detail.get("contract")),
                "<unknown>",
            )
            logger.info(
                "Analyzer input: source_file=%s contract=%s source_bytes=%d functions=%d",
                contract_info.get("target_contract", {}).get("path", "<unknown>"),
                contract_name,
                len(contract_info.get("source_code", "")),
                len(contract_info.get("function_details", [])),
            )
            with create_progress_spinner("Analyzing contract vulnerabilities") as progress:
                task = progress.add_task("Searching for vulnerability patterns...")
                retrieval_queries = self._build_retrieval_queries(contract_info)
                
                # Check if retriever is enabled
                if self.retriever:
                    relevant_docs = self._retrieve_security_context(retrieval_queries)
                    logger.info("Analyzer RAG results: %d", len(relevant_docs))
                    progress.update(task, description=f"Found {len(relevant_docs)} relevant patterns")
                else:
                    relevant_docs = []
                    logger.info("Analyzer RAG results: 0 (disabled)")
                    progress.update(task, description="RAG disabled, using direct analysis")

                # Build prompts
                progress.update(task, description="Constructing analysis prompt...")

                user_prompt = self._construct_analysis_prompt(contract_info, relevant_docs)

                # Call the local LLM for broad review, but never discard
                # deterministic evidence when the local service is unavailable.
                progress.update(task, description="Analyzing with LLM...")
                # Optimized system prompt for local 7B coder model
                system_prompt = (
                    "You are a source-grounded Solidity security auditor. Return only valid JSON. "
                    "Perform a structured audit in this exact order: Access Control; External Calls; State Changes; "
                    "Reentrancy; Arithmetic; Timestamp; Randomness; Business Logic; Denial of Service; Selfdestruct. "
                    "For every accepted finding, cite the affected function and explain the concrete source-level condition, "
                    "attacker capability, and impact. Do not infer code, functions, modifiers, or state that is absent from the source. "
                    "Do not report a category merely because a keyword occurs; report it only when the surrounding logic creates a security-relevant condition. "
                    "Use exact function IDs from the supplied summary and calibrate confidence conservatively."
                )
                try:
                    response_text = self._call_llm(system_prompt, user_prompt)
                    logger.info("Analyzer raw LLM response: %s", response_text)
                    vulnerabilities = self._parse_llm_response(response_text)
                    logger.info("Analyzer parsed LLM findings: %d", len(vulnerabilities))
                except Exception as exc:
                    logger.warning("Local LLM analysis unavailable; continuing with deterministic findings: %s", exc)
                    print_warning(f"Local LLM analysis unavailable; using verified static findings: {exc}")
                    vulnerabilities = []

                # Parse results
                progress.update(task, description="Processing results...")
                vulnerabilities = self._add_deterministic_findings(vulnerabilities, contract_info)
                logger.info("Analyzer findings after source/static evidence merge: %d", len(vulnerabilities))
                vulnerabilities = self._validate_findings(vulnerabilities, contract_info)
                vulnerabilities = self._deduplicate_vulnerabilities(vulnerabilities)
                self._attach_code_snippets(vulnerabilities, contract_info)
                logger.info("Analyzer final findings: %s", [v.get("vulnerability_type") for v in vulnerabilities])

                progress.update(task, completed=True)

            return {"vulnerabilities": vulnerabilities}

        except Exception as e:
            import traceback
            traceback.print_exc()
            print_warning(f"Analysis error: {repr(e)}")
            return {"vulnerabilities": [], "error": repr(e)}

    def _deduplicate_vulnerabilities(self, vulnerabilities: list) -> list:
        """Remove redundant findings of the same type in the same functions."""
        merged = {}
        for v in vulnerabilities:
            v_type = v.get("vulnerability_type", "").lower()
            # Sort affected functions for consistent keys
            affected = sorted(v.get("affected_functions", []))
            # Create a unique key based on type and affected functions
            key = (v_type, tuple(affected))
            
            current = merged.get(key)
            if current is None:
                merged[key] = dict(v)
                continue
            current_confidence = self._confidence_value(current.get("confidence_score"))
            new_confidence = self._confidence_value(v.get("confidence_score"))
            stronger, supporting = (v, current) if new_confidence > current_confidence else (current, v)
            merged[key] = dict(stronger)
            supporting_reason = str(supporting.get("reasoning", "")).strip()
            if supporting_reason and supporting_reason not in merged[key].get("reasoning", ""):
                merged[key]["reasoning"] = (
                    f"{merged[key].get('reasoning', '').strip()} Supporting evidence: {supporting_reason}"
                ).strip()
        return list(merged.values())

    @staticmethod
    def _confidence_value(value) -> float:
        try:
            return max(0.0, min(1.0, float(value)))
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _detector_evidence(detector_results) -> List[str]:
        """Collect existing static-analysis text without assigning new categories."""
        evidence = []

        def visit(item):
            if isinstance(item, dict):
                for key in ("check", "detector", "name", "description", "impact"):
                    value = item.get(key)
                    if isinstance(value, str) and value.strip():
                        evidence.append(value.strip())
                for value in item.values():
                    visit(value)
            elif isinstance(item, list):
                for value in item:
                    visit(value)

        visit(detector_results)
        return list(dict.fromkeys(evidence))[:8]

    @staticmethod
    def _security_signals(function_source: str) -> List[str]:
        """Describe observed source features for retrieval, never as findings."""
        source = function_source or ""
        signals = []
        external_calls = list(re.finditer(r"\.(?:call(?:\.value)?|delegatecall|send|transfer)\s*(?:\{|\(|\.value)", source, re.I))
        if external_calls:
            signals.append("external call or value transfer")
        if re.search(r"\.call(?:\.value)?\s*(?:\{|\()", source, re.I):
            signals.append("low-level call")
        if re.search(r"\.delegatecall\s*(?:\{|\()", source, re.I):
            signals.append("delegatecall")
        if re.search(r"\bmsg\.sender\b", source):
            signals.append("msg.sender interaction")
        if re.search(r"\b(?:balances?|credits?|balanceOf)\s*\[", source, re.I):
            signals.append("balance or mapping state access")
        if external_calls and re.search(r"(?:\[[^\]]+\]|\b(?:balance|credit|owner|admin|total)\w*)\s*(?:\+\+|--|[+\-*/]?=)", source[external_calls[0].end():], re.I):
            signals.append("state update after external interaction")
            signals.append("external call before state update")
            signals.append("checks-effects-interactions ordering evidence")
        if re.search(r"\b(?:onlyOwner|onlyRole|hasRole|owner|admin|authorize[dr]?|msg\.sender\s*==)", source, re.I):
            signals.append("authorization or privileged-state evidence")
        if re.search(r"\bselfdestruct\s*\(", source, re.I):
            signals.append("selfdestruct operation")
        if re.search(r"\bblock\.(?:timestamp|number|prevrandao|difficulty|hash)\b|\bblockhash\s*\(", source, re.I):
            signals.append("block-derived value")
        if re.search(r"\b(?:random|rand|lottery|raffle)\b", source, re.I):
            signals.append("randomness-related logic")
        if re.search(r"\b(?:for|while|do)\b", source):
            signals.append("loop")
        if re.search(r"\bunchecked\b|(?:\+|-|\*|/)\s*=|\b\w+\s*[+\-*/]\s*\w+", source):
            signals.append("arithmetic operation")
        return signals

    @staticmethod
    def _state_references(function_source: str) -> List[str]:
        """Return concrete source expressions likely to carry contract state."""
        references = re.findall(r"\b[A-Za-z_]\w*\s*\[[^\]\n]+\]", function_source or "")
        references.extend(re.findall(r"\b(?:owner|admin|administrator|controller|operator|totalSupply|totalBalance)\b", function_source or "", re.I))
        return list(dict.fromkeys(reference.strip() for reference in references))[:8]

    @classmethod
    def _retrieval_category_hints(cls, function_source: str) -> List[str]:
        """Map concrete source evidence to retrieval-only corpus categories.

        These hints only rank already-retrieved documents.  They do not create
        analyzer findings or change the vulnerability decision pipeline.
        """
        source = function_source or ""
        signals = set(cls._security_signals(source))
        hints = []
        if {"low-level call", "state update after external interaction"}.issubset(signals):
            hints.append("reentrancy")
        if {"block-derived value", "randomness-related logic"}.issubset(signals):
            hints.append("bad_randomness")
        if "low-level call" in signals and not re.search(
            r"\b(?:success|ok|sent)\b|require\s*\([^;]*(?:call|send|delegatecall)", source, re.I
        ):
            hints.append("unchecked_low_level_calls")
        protected = re.search(
            r"\b(?:onlyOwner|onlyRole|hasRole)\b|require\s*\([^;]*(?:msg\.sender\s*==|hasRole)", source, re.I
        )
        privileged_action = re.search(
            r"\bselfdestruct\s*\(|\b(?:owner|admin)\s*=|"
            r"\b(?:balance|reward)\s*\[\s*(?!msg\.sender\b)[^\]]+\]\s*=|"
            r"address\s*\(\s*this\s*\)\.balance|\breward\s*\[\s*msg\.sender\s*\]\s*\+=",
            source,
            re.I,
        )
        if privileged_action and not protected:
            hints.append("access_control")
        if "loop" in signals:
            hints.append("denial_of_service")
        return hints

    def _build_query_text(self, contract_info: Dict, function_detail: Dict = None) -> str:
        """Build one source-grounded, structured security retrieval query."""
        detail = function_detail or {}
        source_code = contract_info.get("source_code", "") or ""
        contract_name = detail.get("contract") or contract_info.get("target_contract", {}).get("name") or contract_info.get("target_contract", {}).get("filename") or "<unknown>"
        pragma_match = re.search(r"\bpragma\s+solidity\s+([^;]+);", source_code)
        pragma = pragma_match.group(1).strip() if pragma_match else "<unknown>"
        function_source = detail.get("content") or ""
        function_id = detail.get("function_id") or detail.get("function") or "<contract context>"
        signals = self._security_signals(function_source)
        retrieval_hints = self._retrieval_category_hints(function_source)
        state_references = self._state_references(function_source)
        known_categories = contract_info.get("static_vulnerability_categories", []) or []
        detector_evidence = self._detector_evidence(contract_info.get("detector_results", []))
        sections = [
            f"Contract: {contract_name}", f"Pragma: {pragma}", "", "Function:", function_id,
            f"Visibility: {detail.get('visibility', '<unknown>')}",
            f"Modifiers: {', '.join(detail.get('modifiers') or []) or 'none'}",
            f"Calls: {', '.join(detail.get('called_functions') or []) or 'none'}",
            f"State references: {', '.join(state_references) or 'none identified'}",
            f"Security evidence: {', '.join(signals) or 'none identified'}",
            f"Retrieval security categories: {', '.join(retrieval_hints) or 'none inferred'}",
        ]
        if known_categories:
            sections.append(f"Known analyzer categories: {', '.join(map(str, known_categories))}")
        if detector_evidence:
            sections.append(f"Static-analysis findings: {' | '.join(detector_evidence)}")
        if function_source:
            sections.extend(("Function source:", function_source[:2400]))
        return "\n".join(sections)

    def _build_retrieval_queries(self, contract_info: Dict) -> List[str]:
        """Query every externally callable function with observed security evidence."""
        details = contract_info.get("function_details", []) or []
        selected = []
        for index, detail in enumerate(details):
            signals = self._security_signals(detail.get("content") or "")
            if signals and detail.get("visibility") in {"public", "external"}:
                selected.append((index, detail))
        if not selected:
            selected = [
                (index, detail)
                for index, detail in enumerate(details)
                if detail.get("content") or detail.get("function_id")
            ]
        return [self._build_query_text(contract_info, detail) for _, detail in selected] or [self._build_query_text(contract_info)]

    @staticmethod
    def _query_category_hints(query: str) -> set:
        match = re.search(r"^Retrieval security categories:\s*(.+)$", query, re.MULTILINE)
        if not match or match.group(1).strip() == "none inferred":
            return set()
        return {item.strip() for item in match.group(1).split(",") if item.strip()}

    def _rank_retrieval_candidate(self, query: str, document: Document, distance: float) -> float:
        """Rank vector candidates with observed-query/category evidence only."""
        metadata = document.metadata or {}
        labels = {item.strip() for item in str(metadata.get("vuln_categories", "")).split(",") if item.strip()}
        hints = self._query_category_hints(query)
        # Chroma's L2 score is lower-is-better.  Category agreement is a
        # ranking feature, not a new finding about the analyzed contract.
        score = -float(distance)
        if hints:
            if labels & hints:
                score += 3.0
            elif labels:
                score -= 0.75
            else:
                score -= 1.25
        elif not labels:
            score -= 0.35
        if metadata.get("vuln_lines"):
            score += 0.15
        return score

    def _retrieve_security_context(self, queries: List[str]) -> List[Document]:
        """Fetch vector candidates, rank security evidence, then keep five docs."""
        ranked = []
        seen = set()
        vectorstore = getattr(self.retriever, "vectorstore", None)
        for query in queries:
            if vectorstore and hasattr(vectorstore, "similarity_search_with_score"):
                candidates = vectorstore.similarity_search_with_score(query, k=self.RAG_CANDIDATE_K)
            else:
                candidates = [(document, 0.0) for document in self.retriever.invoke(query)]
            for document, distance in candidates:
                metadata = document.metadata or {}
                identity = (metadata.get("filename"), metadata.get("source"), metadata.get("start_line"), metadata.get("end_line"), document.page_content)
                if identity not in seen:
                    seen.add(identity)
                    ranked.append((self._rank_retrieval_candidate(query, document, distance), document))
        ranked.sort(key=lambda item: item[0], reverse=True)
        return [document for _, document in ranked[:self.RAG_FINAL_K]]

    @staticmethod
    def _add_deterministic_findings(vulnerabilities: list, contract_info: Dict) -> list:
        """Merge direct source and static evidence that must not depend on LLM output.

        This deliberately works per externally callable function.  A contract-wide
        ``onlyOwner`` search is unsafe: one protected function must not protect an
        unrelated public function.
        """
        existing = {str(item.get("vulnerability_type", "")).lower() for item in vulnerabilities}
        findings = [item for item in vulnerabilities if item.get("vulnerability_type") != "unknown"]
        details = AnalyzerAgent._source_function_details(contract_info)

        def protected(detail):
            modifiers = " ".join(detail.get("modifiers", []) or [])
            body = detail.get("content", "") or ""
            return bool(re.search(
                r"(?:only(?:owner|admin|role)|auth|authorized|admin|role)", modifiers, re.I
            ) or re.search(
                r"(?:onlyOwner|onlyRole|hasRole|_checkRole|require\s*\([^;]*(?:msg\.sender\s*==\s*\w+|\w+\s*==\s*msg\.sender)|if\s*\([^)]*(?:msg\.sender\s*!=|!hasRole))",
                body, re.I
            ))

        def public_or_external(detail):
            return (
                str(detail.get("function", "")).lower() != "constructor"
                and str(detail.get("visibility", "")).lower() in {"public", "external"}
            )

        def privileged_write(detail):
            body = detail.get("content", "") or ""
            # Assignment to a privilege-bearing state variable is a privileged
            # administration operation.  User-owned balance writes are excluded.
            return bool(re.search(
                r"\b(?:owner|admin(?:istrator)?|controller|operator|privileged|roles?)\b\s*(?:\[[^\]]+\])?\s*=",
                body, re.I
            ))

        direct_rules = [
            ("access_control", 0.90, "High", "Restrict the privileged operation with an authorization check.",
             lambda detail: public_or_external(detail) and privileged_write(detail) and not protected(detail),
             "An externally callable function changes privileged state without an authorization check."),
        ]
        for vuln_type, confidence, severity, remediation, predicate, evidence in direct_rules:
            affected = [detail["function_id"] for detail in details if predicate(detail)]
            if affected and not any(
                str(item.get("vulnerability_type", "")).lower() == vuln_type
                and set(item.get("affected_functions", []) or []) == set(affected)
                for item in findings
            ):
                findings.append({
                    "vulnerability_type": vuln_type, "confidence_score": confidence,
                    "reasoning": f"Deterministic source evidence: {evidence}",
                    "affected_functions": affected, "impact": severity, "severity": severity,
                    "remediation": remediation,
                    "exploitation_scenario": "Any account can invoke the affected externally callable function.",
                })
                existing.add(vuln_type)

        def add_access_control_finding(affected, confidence, reasoning, remediation, operation=None):
            """Add source-confirmed access-control evidence without collapsing other functions."""
            affected = list(dict.fromkeys(affected))
            if not affected or any(
                str(item.get("vulnerability_type", "")).lower() == "access_control"
                and set(item.get("affected_functions", []) or []) == set(affected)
                for item in findings
            ):
                return
            item = {
                "vulnerability_type": "access_control", "confidence_score": confidence,
                "reasoning": f"Deterministic source evidence: {reasoning}",
                "affected_functions": affected, "impact": "High", "severity": "High",
                "remediation": remediation,
                "exploitation_scenario": "Any account can invoke the affected externally callable function.",
            }
            if operation:
                item["security_operation"] = operation
            findings.append(item)

        unprotected_selfdestruct = [
            detail["function_id"] for detail in details
            if public_or_external(detail)
            and re.search(r"\bselfdestruct\s*\(", detail.get("content", "") or "", re.I)
            and not protected(detail)
        ]
        add_access_control_finding(
            unprotected_selfdestruct, 0.95,
            "An externally callable function reaches selfdestruct without an authorization check.",
            "Remove selfdestruct or strictly protect it with authorization.",
            operation="selfdestruct",
        )
        if unprotected_selfdestruct and not any(
            str(item.get("vulnerability_type", "")).lower() == "dangerous_selfdestruct"
            for item in findings
        ):
            findings.append({
                "vulnerability_type": "dangerous_selfdestruct", "confidence_score": 0.95,
                "reasoning": "Deterministic source evidence: selfdestruct is callable without authorization.",
                "affected_functions": unprotected_selfdestruct, "impact": "High", "severity": "High",
                "remediation": "Remove selfdestruct or strictly protect it with authorization.",
                "exploitation_scenario": "Any caller can trigger selfdestruct.",
                "security_operation": "selfdestruct",
            })

        caller_entitlement_write = [
            detail["function_id"] for detail in details
            if public_or_external(detail) and not protected(detail)
            and re.search(r"\b(?:add|grant|allocate|credit|mint)\w*\s*\([^)]*\b(?:uint|int)\d*\s+\w+", detail.get("content", ""), re.I)
            and re.search(r"\b(?:reward|credit|entitlement|allowance)\w*\s*\[\s*msg\.sender\s*\]\s*(?:\+=|=)", detail.get("content", ""), re.I)
        ]
        add_access_control_finding(
            caller_entitlement_write, 0.90,
            "An externally callable entitlement-allocation function increases caller-controlled reward or credit state without authorization.",
            "Restrict entitlement allocation to an authorized role or validate the allocation against an approved source.",
        )

        unrestricted_emergency_withdrawal = [
            detail["function_id"] for detail in details
            if public_or_external(detail) and not protected(detail)
            and re.search(r"\b(?:emergency|sweep|rescue)\w*\s*\(", detail.get("content", ""), re.I)
            and re.search(r"(?:payable\s*\(\s*msg\.sender\s*\)|msg\.sender)\s*\.\s*(?:transfer|send|call)\s*(?:\{[^}]*\})?\s*\(\s*address\s*\(\s*this\s*\)\.balance", detail.get("content", ""), re.I)
        ]
        add_access_control_finding(
            unrestricted_emergency_withdrawal, 0.95,
            "An externally callable emergency-style function transfers the contract's full balance without authorization.",
            "Restrict emergency withdrawal of contract-held funds to an authorized role.",
        )

        arbitrary_balance_write = [
            detail["function_id"] for detail in details
            if public_or_external(detail) and not protected(detail)
            and re.search(r"\b(?:set|update|assign)\w*\s*\([^)]*\baddress\s+\w+[^)]*\b(?:u?int)\d*\s+\w+", detail.get("content", ""), re.I)
            and re.search(r"\b(?:balances?|credits?)\s*\[\s*(?!msg\.sender\b)[^\]]+\]\s*=", detail.get("content", ""), re.I)
        ]
        add_access_control_finding(
            arbitrary_balance_write, 0.90,
            "An externally callable administrative setter assigns another user's financial balance without authorization.",
            "Restrict balance administration to an authorized role and validate the update authority.",
        )

        unchecked_calls = []
        for detail in details:
            source = detail.get("content", "") or ""
            low_level_call = re.search(r"\.call\s*(?:\{[^}]*\}\s*)?\(", source, re.I)
            checked_call = re.search(
                r"\(\s*bool\s+(success|ok|sent)\b[^;]*=\s*[^;]*\.call\s*(?:\{[^}]*\}\s*)?\([^;]*;"
                r"[\s\S]*?(?:require\s*\(\s*\1\b|if\s*\(\s*!\s*\1\b)",
                source,
                re.I,
            )
            if public_or_external(detail) and low_level_call and not checked_call:
                unchecked_calls.append(detail["function_id"])
        if unchecked_calls and not any(
            str(item.get("vulnerability_type", "")).lower() == "unchecked_low_level_calls"
            and set(item.get("affected_functions", []) or []) == set(unchecked_calls)
            for item in findings
        ):
            findings.append({
                "vulnerability_type": "unchecked_low_level_calls", "confidence_score": 0.90,
                "reasoning": "Deterministic source evidence: A low-level call return value is not checked in the affected function.",
                "affected_functions": unchecked_calls, "impact": "High", "severity": "High",
                "remediation": "Check the low-level call result and revert or handle failure explicitly.",
                "exploitation_scenario": "A failed external call can be ignored while execution continues.",
            })

        # Slither is an independent signal.  Preserve its high-signal suicidal
        # result even when a model returns an empty list; direct source checks
        # above remain the authority for the affected function and remediation.
        static_descriptions = AnalyzerAgent._detector_descriptions(contract_info.get("detector_results", []))
        logger.info("Analyzer static-analysis findings: %s", static_descriptions)
        if not unprotected_selfdestruct and any(
            re.search(r"\b(?:suicid(?:al|e)?|selfdestruct|destruct)\b", description, re.I)
            for description in static_descriptions
        ):
            affected = [detail["function_id"] for detail in details if re.search(r"\bselfdestruct\s*\(", detail.get("content", ""), re.I)]
            if affected:
                findings.append({
                    "vulnerability_type": "access_control", "confidence_score": 0.90,
                    "reasoning": "Static-analysis evidence: Slither reported an unrestricted destruction path. " + static_descriptions[0],
                    "affected_functions": affected, "impact": "High", "severity": "High",
                    "remediation": "Remove selfdestruct or strictly protect it with authorization.",
                    "exploitation_scenario": "Any account can invoke the reported destruction path.",
                    "security_operation": "selfdestruct",
                })
                existing.add("access_control")

        rules = [
            ("reentrancy", 0.95, "High", "Apply checks-effects-interactions and a reentrancy guard.",
             lambda text: re.search(r"\.call\s*\{[^}]*value\s*:", text, re.I) and re.search(r"\.call[\s\S]*?(?:balances|\w+)\s*\[?[^;]*[-+]?=", text, re.I)),
            ("bad_randomness", 0.80, "High", "Use a verifiable randomness source instead of miner-influenced block values.",
             lambda text: re.search(r"block\.timestamp", text)
             and re.search(r"\b(?:random|rand|lottery|raffle|winner)\b|keccak256\s*\(|block\.(?:prevrandao|difficulty|hash)\b|blockhash\s*\(", text, re.I)),
            ("timestamp_dependence", 0.65, "Medium", "Avoid using miner-influenced time in security-sensitive decisions.",
             lambda text: re.search(r"block\.timestamp", text)),
            ("integer_overflow", 0.75, "Medium", "Remove unchecked arithmetic or validate bounds before state updates.",
             lambda text: re.search(r"unchecked\s*\{[\s\S]*?(?:\+\+|--|\+=|-=|\*=)", text, re.I)),
            ("denial_of_service", 0.70, "Medium", "Use pull payments or bounded batches for recipient processing.",
             lambda text: re.search(r"for\s*\([^)]*;[^)]*\.length[\s\S]*?\.(?:transfer|send|call)\s*\(", text, re.I)),
        ]
        for vuln_type, confidence, severity, remediation, predicate in rules:
            affected = [detail["function_id"] for detail in details if predicate(detail.get("content") or "")]
            if not affected or any(
                str(item.get("vulnerability_type", "")).lower() == vuln_type
                and set(item.get("affected_functions", []) or []) == set(affected)
                for item in findings
            ):
                continue
            findings.append({
                "vulnerability_type": vuln_type, "confidence_score": confidence,
                "reasoning": f"Deterministic source evidence found in {', '.join(affected)}.",
                "affected_functions": affected, "impact": severity, "severity": severity,
                "remediation": remediation, "exploitation_scenario": "Confirmed by function-scoped deterministic source analysis.",
            })
        return findings

    @staticmethod
    def _detector_descriptions(detector_results) -> list:
        """Extract Slither result text without assuming a specific result shape."""
        descriptions = []

        def visit(value):
            if isinstance(value, dict):
                for key in ("description", "check", "markdown"):
                    if isinstance(value.get(key), str):
                        descriptions.append(value[key].replace("\n", " ").strip())
                for nested in value.values():
                    visit(nested)
            elif isinstance(value, (list, tuple)):
                for nested in value:
                    visit(nested)

        visit(detector_results)
        return list(dict.fromkeys(description for description in descriptions if description))

    @staticmethod
    def _source_function_details(contract_info: Dict) -> list:
        """Return function metadata, falling back to the uploaded source when needed."""
        details = [dict(detail) for detail in contract_info.get("function_details", [])]
        if details and all(detail.get("content") for detail in details):
            return details

        source = contract_info.get("source_code", "")
        by_name = {detail.get("function"): detail for detail in details if detail.get("function")}
        pattern = re.compile(r"function\s+([A-Za-z_]\w*)\s*\([^)]*\)\s*([^\{;]*)\{", re.I)
        for match in pattern.finditer(source):
            depth, index = 1, match.end()
            while index < len(source) and depth:
                depth += (source[index] == "{") - (source[index] == "}")
                index += 1
            header = match.group(2)
            name = match.group(1)
            detail = dict(by_name.get(name, {}))
            detail.setdefault("function_id", f"{name}()")
            detail.setdefault("function", name)
            detail["visibility"] = "external" if re.search(r"\bexternal\b", header) else ("public" if re.search(r"\bpublic\b", header) else detail.get("visibility", ""))
            detail["content"] = source[match.start():index]
            details = [item for item in details if item.get("function") != name] + [detail]
        return details

    @staticmethod
    def _normalize_function_reference_for_lookup(value, allowed: set,
                                                 function_details: list = None,
                                                 source_code: str = "") -> str | None:
        """Resolve an LLM function reference to a known canonical function ID.

        LLMs occasionally append analysis-specific identifiers (for example,
        ``withdraw(uint256)_0x6d9485e7``).  Those identifiers are not part of a
        Solidity ABI signature, so they must be removed before matching.  This
        method is deliberately lookup-only: callers retain the original value
        for logs and report output.

        Bare names and ``()`` are resolved only when the target has a single
        overload with that name.  This prevents a generated suffix from
        accidentally selecting the wrong overloaded function.
        """
        if not isinstance(value, str):
            return None

        candidate = value.strip()
        if not candidate:
            return None

        details = function_details or []

        # Function summaries supplied to the LLM include visibility and call
        # metadata.  Recover the canonical Solidity ID from that presentation
        # form before treating it as an unresolved external reference.
        described_function = re.search(r"\bfunction\s+([A-Za-z_]\w*)\s*\(", candidate, re.I)
        if described_function:
            name = described_function.group(1)
            matches = [function_id for function_id in allowed if function_id.split("(", 1)[0] == name]
            if len(matches) == 1:
                logger.info("Mapped function summary %r to %s", value, matches[0])
                return matches[0]

        # Models commonly cite static-analysis locations (for example,
        # ``OwnershipBug.sol#11``).  Resolve those against Slither's source
        # line ranges before attempting name matching; this also disambiguates
        # overloaded and inherited declarations.
        line_match = re.search(r"#(?:line:)?(\d+)$", candidate, re.I)
        if line_match:
            line = int(line_match.group(1))
            matches = [
                detail.get("function_id") for detail in details
                if detail.get("function_id")
                and detail.get("start_line") is not None
                and detail.get("end_line") is not None
                and int(detail["start_line"]) <= line <= int(detail["end_line"])
            ]
            if len(matches) == 1:
                logger.info("Mapped affected-function reference %r by line %d to %s", value, line, matches[0])
                return matches[0]
            logger.info("Could not uniquely map affected-function reference %r by line %d", value, line)

        # Support byte/character offsets emitted by AST and compiler tools.
        offset_match = re.search(r"(?:#|@|offset:|byte:)(\d+)$", candidate, re.I)
        if offset_match and source_code:
            offset = int(offset_match.group(1))
            line_starts = [0]
            line_starts.extend(index + 1 for index, char in enumerate(source_code) if char == "\n")
            matches = []
            for detail in details:
                if not detail.get("function_id") or detail.get("start_line") is None or detail.get("end_line") is None:
                    continue
                start_line, end_line = int(detail["start_line"]), int(detail["end_line"])
                if start_line < 1 or end_line > len(line_starts):
                    continue
                start = line_starts[start_line - 1]
                end = line_starts[end_line] if end_line < len(line_starts) else len(source_code)
                if start <= offset < end:
                    matches.append(detail["function_id"])
            if len(matches) == 1:
                logger.info("Mapped affected-function reference %r by byte offset %d to %s", value, offset, matches[0])
                return matches[0]
            logger.info("Could not uniquely map affected-function reference %r by byte offset %d", value, offset)

        # Contract qualification is presentation metadata, not part of the
        # ABI-style IDs stored in ``allowed``.
        short_name = candidate.rsplit(".", 1)[-1].replace(" ", "")

        # Preserve contract qualification when it is supplied.  It is needed
        # to distinguish inherited declarations with matching signatures.
        qualified_match = re.search(r"(?:^|[.:])([A-Za-z_]\w*)\.([A-Za-z_]\w*(?:\([^)]*\))?)$", candidate.replace(" ", ""))
        if qualified_match:
            contract_name, function_ref = qualified_match.groups()
            qualified = [
                detail.get("function_id") for detail in details
                if str(detail.get("contract", "")).lower() == contract_name.lower()
                and detail.get("function_id")
                and (detail["function_id"] == function_ref or detail["function_id"].split("(", 1)[0] == function_ref.rstrip("()"))
            ]
            if len(qualified) == 1:
                logger.info("Mapped qualified affected-function reference %r to %s", value, qualified[0])
                return qualified[0]

        # Strip trailing analysis/compiler artifacts, but only when they are
        # separated from the function reference.  Supported artifacts include
        # hex hashes, numeric temporary IDs, UUID-like hex IDs, and long
        # generated hashes.  Repeating the substitution handles compound IDs.
        artifact_suffix = re.compile(
            r"(?:[_$#@:]+(?:0x[0-9a-f]+|[0-9]+|[0-9a-f]{8,}|[a-z0-9]{16,}|"
            r"(?:tmp|temp|id|function|fn|compiler)[_-]?[a-z0-9]+))+$",
            re.IGNORECASE,
        )
        normalized = artifact_suffix.sub("", short_name)

        if normalized in allowed:
            logger.info("Mapped affected-function reference %r directly to %s", value, normalized)
            return normalized

        # A four-byte ABI selector is enough to identify a non-overloaded
        # signature.  Some models surface that selector instead of the
        # human-readable function ID supplied in the prompt.
        selector = normalized.lower()
        if re.fullmatch(r"0x[0-9a-f]{8}", selector):
            matches = [
                function_id for function_id in allowed
                if "0x" + keccak(text=function_id).hex()[:8] == selector
            ]
            if len(matches) == 1:
                logger.info("Mapped selector %r to %s", value, matches[0])
                return matches[0]

        if re.fullmatch(r"0x[0-9a-f]{64}", selector):
            matches = [
                function_id for function_id in allowed
                if "0x" + keccak(text=function_id).hex() == selector
            ]
            if len(matches) == 1:
                logger.info("Mapped function-signature hash %r to %s", value, matches[0])
                return matches[0]

        name = normalized.split("(", 1)[0]
        matches = [function_id for function_id in allowed if function_id.split("(", 1)[0] == name]
        # Signature-less references (including ``withdraw()``) are only safe
        # when the contract has a single overload with that name.
        if len(matches) == 1:
            logger.info("Mapped affected-function reference %r by name to %s", value, matches[0])
            return matches[0]
        logger.info("Unable to map affected-function reference %r", value)
        return None

    @classmethod
    def _normalize_affected_functions_for_lookup(cls, values, allowed: set,
                                                 function_details: list = None,
                                                 source_code: str = "") -> List[str]:
        """Return unique canonical IDs for lookup without changing report labels."""
        normalized = []
        for value in values or []:
            resolved = cls._normalize_function_reference_for_lookup(
                value, allowed, function_details, source_code
            )
            if resolved:
                if resolved not in normalized:
                    normalized.append(resolved)
            elif not allowed or str(value).startswith("0x"):
                if value not in normalized:
                    normalized.append(value)
        return normalized

    @staticmethod
    def _build_grounded_exploitation_scenario(vuln_type: str, affected_functions: list, source_code: str, reasoning: str) -> str:
        """Construct a step-by-step, control-flow accurate exploitation scenario that never contradicts explicit require statements or state logic."""
        v_type = str(vuln_type).lower()
        func_str = ", ".join(affected_functions) if affected_functions else "target function"

        if "reentrancy" in v_type:
            return (
                "1. Attacker deposits funds into the contract to establish a valid recorded balance.\n"
                f"2. Attacker calls `{func_str}` requesting a withdrawal within their recorded balance.\n"
                "3. The contract performs an external ETH transfer call to `msg.sender` before updating internal balance state.\n"
                f"4. Attacker's receive/fallback function intercepts execution and re-enters `{func_str}`.\n"
                "5. Because the balance state update has not yet occurred, the re-entrant invocation passes the balance check again.\n"
                "6. Repeated re-entrant calls drain additional ETH from the contract before the original invocation updates the balance."
            )

        if "access" in v_type or "control" in v_type:
            return (
                f"1. Attacker identifies that `{func_str}` is externally callable without an authorization check (such as `onlyOwner` or role verification).\n"
                f"2. Attacker invokes `{func_str}` directly from an unauthorized account.\n"
                f"3. Contract executes the state modification without verifying caller permissions."
            )

        if "unchecked" in v_type and "call" in v_type:
            return (
                f"1. Attacker calls `{func_str}` under parameters causing the low-level call to revert or fail.\n"
                f"2. Because the return value of the call is not checked, execution continues past the failure.\n"
                f"3. Subsequent state updates proceed as if the call succeeded, leaving the contract in an inconsistent state."
            )

        if "timestamp" in v_type:
            return (
                f"1. A miner/validator observes a call to `{func_str}` where execution depends on `block.timestamp`.\n"
                f"2. The miner manipulates the block timestamp within acceptable drift bounds.\n"
                f"3. The manipulated timestamp forces the condition in `{func_str}` to evaluate favorably for the miner."
            )

        if "random" in v_type:
            return (
                f"1. Attacker inspects block-derived properties (`block.timestamp`, `block.prevrandao`, `blockhash`) used in `{func_str}`.\n"
                f"2. Attacker pre-computes the pseudo-random result off-chain before submitting a transaction.\n"
                f"3. Attacker submits transactions only when the pre-computed outcome is winning."
            )

        return (
            f"1. Attacker identifies vulnerable control flow in `{func_str}`.\n"
            f"2. Attacker calls `{func_str}` triggering the vulnerability condition.\n"
            f"3. Contract executes state modification violating security invariants."
        )

    @staticmethod
    def _validate_findings(vulnerabilities: list, contract_info: Dict) -> list:
        """Validate references and enforce strict evidence-grounded correctness."""
        details = contract_info.get("function_details", [])
        source_code = contract_info.get("source_code", "") or ""
        allowed = {detail.get("function_id") for detail in details if detail.get("function_id")}
        validated = []

        _legacy_pragma = bool(re.search(r"pragma\s+solidity\s+[\^~]?0\.[0-7]\b", source_code))
        _has_timestamp = bool(re.search(r"\b(?:block\.timestamp|now|block\.number|blockhash|block\.prevrandao)\b", source_code))

        for finding in vulnerabilities:
            if not isinstance(finding, dict) or not finding.get("vulnerability_type"):
                continue

            vuln_type = str(finding.get("vulnerability_type", "")).strip()
            vuln_type_lower = vuln_type.lower()

            raw_affected = finding.get("affected_functions", [])
            affected = AnalyzerAgent._normalize_affected_functions_for_lookup(
                raw_affected, allowed, details, source_code
            )
            if not affected:
                logger.warning("Discarding finding %r with non-existent functions %r", vuln_type, raw_affected)
                continue

            item = dict(finding)
            item["affected_functions"] = affected

            # Collect source contents of affected functions
            affected_contents = []
            for func_id in affected:
                fn_detail = next((d for d in details if d.get("function_id") == func_id), {})
                if fn_detail.get("content"):
                    affected_contents.append((func_id, fn_detail, fn_detail["content"]))

            if affected_contents:
                # 1. TIMESTAMP validation: Must have block.timestamp/derived logic in source & affected function
                if "timestamp" in vuln_type_lower:
                    if not _has_timestamp:
                        logger.warning("Discarding TIMESTAMP finding %r: contract has no timestamp logic.", vuln_type)
                        continue
                    func_has_ts = any(
                        re.search(r"\b(?:block\.timestamp|now)\b", content)
                        for _, _, content in affected_contents
                    )
                    if not func_has_ts:
                        logger.warning("Discarding TIMESTAMP finding %r: affected functions contain no timestamp logic.", vuln_type)
                        continue

                # 2. ARITHMETIC validation: Must not report standard ^0.8.x arithmetic without unchecked{}
                if any(marker in vuln_type_lower for marker in ("arithmetic", "overflow", "underflow")):
                    is_vulnerable_arith = False
                    for _, _, content in affected_contents:
                        if not _legacy_pragma:
                            # Solidity 0.8+: must be inside an unchecked block
                            if re.search(r"\bunchecked\s*\{[\s\S]*?(?:\+\+|--|[+\-*]=|\+|\-|\*|/)", content, re.I):
                                is_vulnerable_arith = True
                                break
                        else:
                            # Pre-0.8: bare arithmetic without SafeMath
                            if not re.search(r"\bSafeMath\b", source_code, re.I):
                                if re.search(r"[+\-*/]=|\b[A-Za-z_]\w*\s*=\s*[A-Za-z_]\w*\s*[-+]", content):
                                    if not re.search(r"(?:require|assert)\s*\([^;]*\b(?:>=|<=|>|<)\b", content):
                                        is_vulnerable_arith = True
                                        break
                    if not is_vulnerable_arith:
                        logger.warning("Discarding ARITHMETIC finding %r: checked arithmetic in 0.8+ or safe in pre-0.8.", vuln_type)
                        continue

                # 3. UNCHECKED_LOW_LEVEL_CALLS validation: Must have a low level call whose return value is un-checked
                if "unchecked" in vuln_type_lower and "call" in vuln_type_lower:
                    has_unchecked = False
                    for _, _, content in affected_contents:
                        call = re.search(r"\.(?:call\s*(?:\{[^}]*\}\s*)?\(|send\s*\(|delegatecall\s*(?:\{[^}]*\}\s*)?\()", content, re.I)
                        if call:
                            checked = re.search(
                                r"\(\s*bool\s+(?:success|ok|sent)\b[^;]*=\s*[^;]*\.(?:call|send|delegatecall)"
                                r"[\s\S]*?(?:require\s*\(\s*(?:success|ok|sent)\b|if\s*\(\s*!\s*(?:success|ok|sent)\b)",
                                content, re.I
                            )
                            if not checked:
                                has_unchecked = True
                                break
                    if not has_unchecked:
                        logger.warning("Discarding UNCHECKED_LOW_LEVEL_CALLS finding %r: call return value is explicitly checked.", vuln_type)
                        continue

                # 4. ACCESS_CONTROL validation: Must be an un-guarded privileged function
                if "access" in vuln_type_lower and "control" in vuln_type_lower:
                    valid_access = False
                    for _, detail, content in affected_contents:
                        vis = str(detail.get("visibility", "")).lower()
                        if vis not in {"public", "external"}:
                            continue
                        mods = " ".join(detail.get("modifiers", []) or [])
                        protected = bool(re.search(
                            r"(?:only(?:owner|admin|role)|auth|authorized|admin|role)", mods, re.I
                        ) or re.search(
                            r"(?:onlyOwner|onlyRole|hasRole|_checkRole|require\s*\([^;]*(?:msg\.sender\s*==|hasRole)|if\s*\([^)]*(?:msg\.sender\s*!=|!hasRole))",
                            content, re.I
                        ))
                        privileged_action = bool(re.search(
                            r"\bselfdestruct\s*\(|\b(?:owner|admin)\s*=|"
                            r"\b(?:reward|credit)\s*\[\s*msg\.sender\s*\]\s*\+=|"
                            r"address\s*\(\s*this\s*\)\.balance|"
                            r"\btx\.origin\b",
                            content, re.I
                        ))
                        if privileged_action and not protected:
                            valid_access = True
                            break
                        elif not protected and re.search(r"\b(?:set|update|grant|mint|withdraw|destroy)\b", detail.get("function", ""), re.I):
                            valid_access = True
                            break
                    if not valid_access:
                        logger.warning("Discarding ACCESS_CONTROL finding %r: function is protected or contains no un-guarded privileged write.", vuln_type)
                        continue

                # 5. REENTRANCY validation: Must have external call before state update and no nonReentrant guard
                if "reentrancy" in vuln_type_lower:
                    reentrant_funcs = []
                    for func_id, detail, content in affected_contents:
                        call = re.search(
                            r"\.(?:call\s*(?:\{[^}]*\}\s*)?\(|call\.value\s*\(|send\s*\(|transfer\s*\(|delegatecall\s*(?:\{[^}]*\}\s*)?\()",
                            content, re.I
                        )
                        state_after_call = call and re.search(
                            r"\b[A-Za-z_]\w*(?:\s*\[[^\]]+\]|\s*\.\w+)?\s*(?:\+\+|--|[+\-*/]?=)(?!=)",
                            content[call.end():],
                        )
                        has_guard = re.search(r"\bnonReentrant\b", content, re.I) or re.search(r"\bnonReentrant\b", " ".join(detail.get("modifiers", []) or []), re.I)
                        if call and state_after_call and not has_guard:
                            reentrant_funcs.append(func_id)
                    if not reentrant_funcs:
                        logger.warning("Discarding REENTRANCY finding %r: no external call before state update found or protected by guard.", vuln_type)
                        continue
                    item["affected_functions"] = reentrant_funcs

            # Ground exploitation scenario
            item["exploitation_scenario"] = AnalyzerAgent._build_grounded_exploitation_scenario(
                vuln_type, item["affected_functions"], source_code, item.get("reasoning", "")
            )

            validated.append(item)
        return validated

    def _summarize_detector_results(self, detector_results) -> str:
        """
        Traverse the nested detector_results structure and return a bullet-point summary.
        Extract key 'description' fields from the findings.
        """
        summary_lines = []

        def process_item(item):
            if isinstance(item, dict):
                desc = item.get("description")
                if desc:
                    clean_desc = desc.strip().replace("\n", " ")
                    if clean_desc not in summary_lines:
                        summary_lines.append(clean_desc)
                for value in item.values():
                    process_item(value)
            elif isinstance(item, list):
                for sub_item in item:
                    process_item(sub_item)

        process_item(detector_results)
        if summary_lines:
            bullet_points = "\n".join(f"- {line}" for line in summary_lines)
            return f"\n=== SLITHER DETECTOR INSIGHTS ===\n{bullet_points}\n"
        else:
            return (
                "\n=== SLITHER DETECTOR INSIGHTS ===\nNo issues detected by Slither.\n"
            )

    def _construct_analysis_prompt(
        self, contract_info: Dict, relevant_docs: List[Document]
    ) -> str:
        """
        We'll provide the user contract summary, known vulnerability docs,
        plus the slither detector results, then request JSON.
        """
        contract = "\n=== CONTRACT SOURCE CODE ===\n"
        contract += contract_info.get("source_code", "N/A")

        # Summarize user contract
        summary = "=== USER CONTRACT SUMMARY ===\n"
        for fn in contract_info.get("function_details", []):
            summary += f"- Function {fn['function_id']} (visibility={fn['visibility']}), modifiers={fn.get('modifiers', [])}, calls={fn['called_functions']}\n"

        # Add known vulnerability snippets
        snippet_text = "\n=== KNOWN VULNERABILITY SNIPPETS ===\n"
        for i, doc in enumerate(relevant_docs, start=1):
            meta = doc.metadata
            lines_range = f"{meta.get('start_line')} - {meta.get('end_line')}"
            cats = meta.get("vuln_categories", [])
            if cats:
                snippet_text += f"[Snippet] {meta.get('filename','Unknown')} lines {lines_range} cats={cats}\n"
                snippet_text += doc.page_content[:1500]  # truncated
                snippet_text += "\n\n"

        # Slither results
        detector_section = ""
        if "detector_results" in contract_info:
            detector_section = self._summarize_detector_results(
                contract_info["detector_results"]
            )

        # Category guidance
        category_guidance = "\n=== VULNERABILITY CATEGORY GUIDANCE ===\n"
        snippet_categories = set()
        for doc in relevant_docs:
            categories = doc.metadata.get("vuln_categories", "")
            # Chroma metadata only supports scalar values, so categories are
            # stored as a comma-separated string by the document builder.
            if isinstance(categories, str):
                snippet_categories.update(
                    category.strip() for category in categories.split(",") if category.strip()
                )
            elif isinstance(categories, (list, tuple, set)):
                snippet_categories.update(categories)

        for cat, guidance in self.vuln_categories.items():
            priority_note = (
                " (HIGH PRIORITY - MATCHES KNOWN VULNERABILITIES)"
                if cat in snippet_categories
                else ""
            )
            category_guidance += (
                f"## {cat.upper()}{priority_note} ##\n"
                f"Description: {guidance['description']}\n"
                f"Common Patterns:\n- "
                + "\n- ".join(guidance["common_patterns"])
                + "\n"
                f"Detection Strategy: {guidance['detection_strategy']}\n\n"
            )

        # Inter-contract context if it was provided from previous stage
        inter_contract_section = ""
        if "project_context" in contract_info:
            # Use the project_context that was already analyzed and provided
            context = contract_info["project_context"]
            
            # Get ProjectContextLLMAgent to generate the prompt section
            project_context_agent = ProjectContextLLMAgent(self.model_config)
            inter_contract_section = project_context_agent.generate_prompt_section(context)
            
            # Log completion
            stats = context.get('stats', {})
            total_contracts = stats.get('total_contracts', 0)
            total_relationships = stats.get('total_relationships', 0)
            logger.info(f"Using pre-analyzed project context with {total_contracts} contracts and {total_relationships} relationships")
        
        # Task instructions
        instructions = """\
TASK:
1. First conduct a THOROUGH, INDEPENDENT security review of the contract without relying on examples.
   - Review state variables, initialization, access control
   - Examine value flows (ETH and tokens) for manipulation points
   - Identify privilege escalation possibilities
   - Check mathematical operations for precision loss or overflow/underflow
   - Analyze external calls and their security implications

2. After independent analysis, systematically check for ALL vulnerability categories specified.

3. Prioritize BUSINESS LOGIC FLAWS that might be unique to this contract:
   - Economic incentive misalignments
   - State manipulation across transactions
   - Edge cases in mathematical formulas
   - Governance or access control loopholes
   - Transaction ordering dependencies

4. Mark categories as (HIGH PRIORITY) only if you're confident the issue is exploitable.

5. Return all discovered vulnerabilities in the JSON with detailed reasoning.
   - For business logic flaws, use "business_logic" as the vulnerability_type
   - Include specific exploitation scenarios that are realistic
   - Assign confidence scores honestly (prefer false negatives to false positives)

Format findings as:

{
  "vulnerabilities": [{
      "vulnerability_type": "EXACT_CATEGORY_NAME",
      "confidence_score": 0.0-1.0,
      "reasoning": "Detailed analysis showing why this is a vulnerability",
      "affected_functions": ["EXACT_FUNCTION_ID_FROM_USER_CONTRACT_SUMMARY"],
      "impact": "Specific consequences if exploited",
      "exploitation_scenario": "Step-by-step realistic attack scenario"
  }, ...]
}
"""

        full_prompt = (
            contract
            + summary
            + snippet_text
            + detector_section
            + "\n"
            + inter_contract_section
            + "\n"
            + category_guidance
            + "\n"
            + instructions
        )
        return full_prompt

    def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        """
        Use openai.ChatCompletion with the appropriate messaging structure based on model type.
        """
        # Import token tracker
        from utils.token_tracker import token_tracker
        
        # Create messages list based on model capabilities
        if not self.model_config.supports_reasoning(self.model_name):
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
        else:
            messages = [
                {"role": "user", "content": system_prompt + "\n\n" + user_prompt}
            ]

        resp = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages
        )
            
        # Track token usage
        if hasattr(resp, 'usage') and resp.usage:
            token_tracker.log_tokens(
                agent_name="analyzer",
                model_name=self.model_name,
                prompt_tokens=resp.usage.prompt_tokens,
                completion_tokens=resp.usage.completion_tokens,
                total_tokens=resp.usage.total_tokens
            )
        response_text = resp.choices[0].message.content

        with open("raw_llm_response.txt", "w", encoding="utf-8") as f:
            f.write(response_text)

        print("\n========== RAW LLM RESPONSE ==========")
        print(response_text[:1000])
        print("... (full response saved to raw_llm_response.txt)")
        print("=====================================\n")

        return response_text.strip()   
            
    

    def _parse_llm_response(self, response_text: str):
        from utils.json_cleaner import parse_json_safely

        data = parse_json_safely(response_text, default_fallback={}, log_failure=False)
        if "vulnerabilities" in data:
            return data["vulnerabilities"]

        # Local models occasionally produce one malformed finding after a
        # sequence of valid JSON objects. Keep the valid findings instead of
        # discarding the entire audit result.
        candidates = self._extract_vulnerability_objects(response_text)
        if candidates:
            # Recovery is an expected compatibility path for local models; the
            # validated findings are retained and no parsing failure reaches a
            # caller, so this must not be reported as a runtime warning.
            logger.info("Recovered %d valid vulnerability finding(s) from malformed LLM JSON.", len(candidates))
            return candidates

        print("\n========== FAILED RESPONSE ==========")
        print(response_text)
        print("=====================================\n")

        return [{
            "vulnerability_type": "unknown",
            "confidence_score": 0.0,
            "reasoning": "No valid JSON found",
            "affected_functions": [],
            "impact": "",
            "exploitation_scenario": ""
        }]

    @staticmethod
    def _extract_vulnerability_objects(response_text: str) -> list:
        """Return individually parseable objects from a vulnerabilities array."""
        from utils.json_cleaner import parse_json_safely

        array_match = re.search(r'"vulnerabilities"\s*:\s*\[', response_text)
        if not array_match:
            return []

        objects, start, depth, in_string, escaped = [], None, 0, False, False
        for index, char in enumerate(response_text[array_match.end():], start=array_match.end()):
            if in_string:
                if char == '"' and not escaped:
                    in_string = False
                escaped = char == "\\" and not escaped
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                if depth == 0:
                    start = index
                depth += 1
            elif char == "}" and depth:
                depth -= 1
                if depth == 0 and start is not None:
                    item = parse_json_safely(response_text[start:index + 1], default_fallback=None, log_failure=False)
                    if isinstance(item, dict) and item.get("vulnerability_type"):
                        objects.append(item)
            elif char == "]" and depth == 0:
                break
        return objects

    def _attach_code_snippets(self, vulnerabilities: list, contract_info: dict):
        """
        Attach code snippets to vulnerability entries. This function handles both:
        1. Direct matches from function details when source_mapping.content is available
        2. Fallback to searching in source code when direct matches aren't found
        """
        # Create a map of function names to their code content
        fn_map = {}
        print("\n========== FUNCTION MAP ==========")
        for fn in contract_info.get("function_details", []):
            print(
                fn.get("function"),
                "|",
                fn.get("function_id"),
                "| content:",
                fn.get("content") is not None
            )
        print("=================================\n")
        for fn_detail in contract_info.get("function_details", []):
            function_name = fn_detail["function"]
            function_id = fn_detail.get("function_id", function_name)
            content = fn_detail.get("content")

            if not content:
                continue

            fn_map[function_name] = content
            fn_map[function_id] = content

            fn_map[f"{fn_detail['contract']}.{function_name}"] = content
            fn_map[f"{fn_detail['contract']}.{function_id}"] = content

        # Extract code for affected function
        allowed_function_ids = known_function_ids(contract_info.get("function_details", []))
        for vuln in vulnerabilities:
            snippet_list = []
            affected_fns = vuln.get("affected_functions", [])
            print("\n========== VULNERABILITY ==========")
            print(vuln.get("vulnerability_type"))
            print("Affected:", affected_fns)
            print("Available keys:", list(fn_map.keys())[:20])
            print("==================================\n")

            # First try direct matches from function map
            for function_id in self._normalize_affected_functions_for_lookup(
                affected_fns, allowed_function_ids
            ):
                if code_snip := fn_map.get(function_id):
                    snippet_list.append(code_snip)

            # Set the code snippet
            if snippet_list:
                vuln["code_snippet"] = "\n\n".join(snippet_list)
            else:
                # Try to search for relevant code from source code directly if no matches are found
                source_code = contract_info.get("source_code", "")
                if source_code and affected_fns:
                    for function_id in self._normalize_affected_functions_for_lookup(
                        affected_fns, allowed_function_ids
                    ):
                        simple_fn_name = function_id.split('(', 1)[0]

                        # Find in source code directly - basic approach
                        lines = source_code.split('\n')
                        for i, line in enumerate(lines):
                            # Look for function declaration with the name
                            if f"function {simple_fn_name}" in line:
                                # Found function declaration, extract surrounding content
                                start = max(0, i-1)
                                end = min(len(lines), i+15)  # Get ~15 lines of context
                                vuln["code_snippet"] = "\n".join(lines[start:end])
                                break
                        else:
                            continue  # Try next function name if this one wasn't found
                        break  # Exit if we found at least one function
                    else:
                        # If no functions were found after searching all
                        vuln["code_snippet"] = "(No matching function code found)"
                else:
                    vuln["code_snippet"] = "(No matching function code found)"
