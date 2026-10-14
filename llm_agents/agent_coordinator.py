# ==============================
# File: llm_agents/agent_coordinator.py
# ==============================
import os
from typing import Dict
from pathlib import Path
# Import the new function
from rag.doc_db import get_vuln_retriever_from_json
from utils.token_tracker import performance_tracker, token_tracker

# CHANGED: import SkepticAgent
from .agents.analyzer import AnalyzerAgent
from .agents.exploiter import ExploiterAgent
from .agents.generator import GeneratorAgent
from .agents.skeptic import SkepticAgent
from .agents.runner import ExploitRunner
from .agents.project_context_llm import ProjectContextLLMAgent
from .config import ModelConfig

from utils.print_utils import print_step, print_success, print_warning
from utils.token_tracker import performance_tracker

class AgentCoordinator:
    def __init__(self, model_config=None, use_rag=True):
        """
        Initialize the agent coordinator with configurable models.

        Args:
            model_config: Optional ModelConfig instance. If None, default config will be used.
            use_rag: Boolean to enable/disable Retrieval Augmented Generation for analysis.
        """
        self.model_config = model_config or ModelConfig()
        self.use_rag = use_rag

        # Initialize retriever only if RAG is enabled
        # Initialize retriever only if RAG is enabled
        if self.use_rag:
            try:
                PROJECT_ROOT = Path(__file__).resolve().parent.parent

                self.vuln_retriever = get_vuln_retriever_from_json(
                    json_path=str(PROJECT_ROOT / "known_vulnerabilities" / "contract_vulns.json"),
                    base_dataset_dir=str(PROJECT_ROOT / "known_vulnerabilities"),
                    persist_directory=str(PROJECT_ROOT / "chroma_db_v2"),
                    top_k=5,
        )       
                if self.vuln_retriever is None:
                    print_warning("RAG unavailable. Continuing without ChromaDB.")

            except Exception as e:
                print_warning(f"Failed to initialize RAG: {e}")
                self.vuln_retriever = None
        else:
            self.vuln_retriever = None

        self.project_context = ProjectContextLLMAgent(model_config=self.model_config)
        self.analyzer = AnalyzerAgent(self.vuln_retriever, model_config=self.model_config)
        self.skeptic = SkepticAgent(model_config=self.model_config)
        self.exploiter = ExploiterAgent(model_config=self.model_config)
        self.generator = GeneratorAgent(model_config=self.model_config)
        self.runner = ExploitRunner(model_config=self.model_config)

    def analyze_contract(self, contract_info: Dict, auto_run_config: Dict = None) -> Dict:
        from rich.console import Console
        console = Console()

        def log_findings(stage: str, findings: list) -> None:
            console.print(f"[bold]{stage}: {len(findings)} finding(s)[/bold]")
            for finding in findings:
                confidence = finding.get("skeptic_confidence", finding.get("confidence_score", 0))
                console.print(
                    f"  - {finding.get('vulnerability_type')} | confidence={confidence} | "
                    f"functions={finding.get('affected_functions', [])}"
                )

        # Set default auto-run config if none provided
        if auto_run_config is None:
            auto_run_config = {"auto_run": True, "max_retries": 3}

        # Configure runner's max retries
        self.runner.max_retries = auto_run_config.get("max_retries", 3)

        # 1. ProjectContextLLMAgent => inter-contract relationships
        if "contracts_dir" in contract_info and contract_info["contracts_dir"]:
            performance_tracker.start_stage("project_context_agent")
            console.print("[bold blue]🔍 ProjectContextLLMAgent: Analyzing contract relationships...[/bold blue]")
            project_context_results = self.project_context.analyze_project(
                contract_info["contracts_dir"],
                contract_info.get("call_graph")
            )
            
            # Display the project context insights
            insights = project_context_results.get("insights", [])
            dependencies = project_context_results.get("dependencies", [])
            if insights or dependencies:
                console.print(f"[bold green]✓ ProjectContextLLMAgent: Found {len(insights)} insights and {len(dependencies)} dependencies[/bold green]")
                
                if insights:
                    console.print("[bold]Key insights:[/bold]")
                    for i, insight in enumerate(insights[:3]):  # Show top 3 insights
                        console.print(f"  - {insight}")
                    if len(insights) > 3:
                        console.print(f"  - ...and {len(insights) - 3} more insights")
                
                if dependencies:
                    console.print("[bold]Important dependencies:[/bold]")
                    for i, dep in enumerate(dependencies[:3]):  # Show top 3 dependencies
                        console.print(f"  - {dep}")
                    if len(dependencies) > 3:
                        console.print(f"  - ...and {len(dependencies) - 3} more dependencies")
            else:
                console.print("[bold yellow]ProjectContextLLMAgent: No significant insights found[/bold yellow]")
                
            # Add project context to contract_info for the analyzer
            contract_info["project_context"] = project_context_results

        # 2. Analyzer => all vulnerabilities
        performance_tracker.start_stage("analyzer_agent")
        console.print("\n[bold blue]🔍 AnalyzerAgent: Starting vulnerability detection...[/bold blue]")
        vuln_results = self.analyzer.analyze(contract_info)
        vulnerabilities = vuln_results.get("vulnerabilities", [])
        if not vulnerabilities:
            console.print("[bold yellow]AnalyzerAgent: No vulnerabilities found[/bold yellow]")
            return {
                "status": "no_vulnerability_found",
                "rechecked_vulnerabilities": [],
                "generated_pocs": [],
                "poc_metrics": {},
            }

        console.print(f"[bold green]✓ AnalyzerAgent: Found {len(vulnerabilities)} potential vulnerabilities[/bold green]")
        log_findings("Analyzer findings", vulnerabilities)
        for i, v in enumerate(vulnerabilities):
            console.print(f"  - {v.get('vulnerability_type')} (confidence: {v.get('confidence_score', 0):.2f})")

        # 2. Skeptic => re-check validity
        performance_tracker.start_stage("skeptic_agent")
        console.print("\n[bold blue]🧐 SkepticAgent: Re-checking vulnerability validity...[/bold blue]")
        rechecked_vulns = self.skeptic.audit_vulnerabilities(
            contract_info["source_code"],
            vulnerabilities,
            contract_info.get("function_details", []),
            {
                "llm_unavailable": bool(vuln_results.get("llm_error")),
                "llm_error": vuln_results.get("llm_error", ""),
            },
        )

        # Extra deduplication after skeptic
        rechecked_vulns = self.analyzer._deduplicate_vulnerabilities(rechecked_vulns)

        log_findings("Skeptic findings", rechecked_vulns)

        console.print("[bold green]✓ SkepticAgent: Completed verification[/bold green]")
        for i, v in enumerate(rechecked_vulns):
            old_score = v.get('confidence_score', 0)
            new_score = v.get('skeptic_confidence', 0)
            change = "↑" if new_score > old_score else "↓" if new_score < old_score else "→"
            console.print(f"  - {v.get('vulnerability_type')}: {old_score:.2f} {change} {new_score:.2f}")

        # 3. Generate PoCs for high-confidence vulnerabilities
        generated_pocs = []
        poc_metrics = {
            "generated_pocs": 0, "compiled_pocs": 0, "executed_pocs": 0,
            "successful_exploits": 0, "compilation_failures": 0,
            "execution_failures": 0, "repair_attempts": 0,
            "_compile_times": [], "_execution_times": [],
        }
        high_conf_vulns = [
            v for v in rechecked_vulns
            if float(v.get("skeptic_confidence", 0)) >= 0.6
            or (
                any(marker in str(v.get("vulnerability_type", "")).lower() for marker in ("reentrancy", "access", "selfdestruct", "unchecked"))
                and float(v.get("skeptic_confidence", 0)) >= 0.4
            )
        ]

        # Process high confidence vulnerabilities
        if high_conf_vulns:
            performance_tracker.start_stage("exploiter_agent")
            console.print(f"\n[bold blue]💡 ExploiterAgent: Generating exploit plans for {len(high_conf_vulns)} vulnerabilities...[/bold blue]")

            for i, vul in enumerate(high_conf_vulns):
                console.print(f"  Working on {vul.get('vulnerability_type')} (#{i+1}/{len(high_conf_vulns)})...")
                plan_data = self.exploiter.generate_exploit_plan(vul)
                
                # Store the exploit plan for each vulnerability
                poc_info = {
                    "vulnerability": vul,
                    "exploit_plan": plan_data.get("exploit_plan"),
                }
                
                # Skip PoC generation if configured to do so
                if self.model_config.skip_poc_generation:
                    console.print(f"[dim]Skipping PoC generation as requested.[/dim]")
                    generated_pocs.append(poc_info)
                    console.print(f"[bold green]✓ Generated exploit plan for {vul.get('vulnerability_type')}[/bold green]")
                    continue
                
                # Otherwise continue with PoC generation
                performance_tracker.start_stage("generator_agent")
                console.print(f"\n[bold blue]🔧 GeneratorAgent: Creating PoC for {vul.get('vulnerability_type')}...[/bold blue]")

                # First generate the BaseTestWithBalanceLog.sol file if it doesn't exist
                if not os.path.exists("exploit/test/basetest.sol"):
                    base_file = self.generator.generate_basetest_file()
                    console.print(f"[dim]Created base file: {base_file}[/dim]")

                # Generate the PoC for this vulnerability
                # Preserve target metadata so the generator imports the analyzed source by name.
                plan_data["target_contract"] = contract_info.get("target_contract", {})
                console.print("[dim]Generator called.[/dim]")
                poc_data = self.generator.generate(plan_data)
                if poc_data.get("exploit_file"):
                    poc_metrics["generated_pocs"] += 1
                    console.print(f"[bold green]PoC created: {poc_data['exploit_file']}[/bold green]")
                else:
                    console.print(f"[bold red]PoC rejected: {poc_data.get('generation_error', 'no Solidity file created')}[/bold red]")

                # Run and fix the exploit if auto-run is enabled
                if auto_run_config.get("auto_run", True) and poc_data.get("poc_strategy", "executable") == "executable":
                    performance_tracker.start_stage("exploit_runner")
                    console.print(f"\n[bold blue]🔍 ExploitRunner: Testing and fixing PoC...[/bold blue]")
                    run_result = self.runner.run_and_fix_exploit(poc_data)

                    if run_result.get("success"):
                        console.print(f"[bold green]✓ Test executed successfully![/bold green]")
                    else:
                        if run_result.get("retries") > 0:
                            console.print(f"[bold yellow]⚠ Test failed after {run_result.get('retries')} fix attempts[/bold yellow]")
                            console.print(f"[dim]Error: {run_result.get('error', 'Unknown error')}[/dim]")
                        else:
                            console.print(f"[bold red]✗ Test failed and could not be fixed[/bold red]")
                            console.print(f"[dim]Error: {run_result.get('error', 'Unknown error')}[/dim]")

                    # Add execution results to the PoC data
                    poc_data["execution_results"] = {
                        "success": run_result.get("success", False),
                        "compiled": run_result.get("compiled", False),
                        "executed": run_result.get("executed", False),
                        "retries": run_result.get("retries", 0),
                        "compile_error": run_result.get("compile_error", ""),
                        "runtime_error": run_result.get("runtime_error", ""),
                        "failure_reason": run_result.get("failure_reason", ""),
                        "stdout": run_result.get("stdout", ""),
                        "stderr": run_result.get("stderr", ""),
                        "gas_used": run_result.get("gas_used"),
                        "execution_trace": run_result.get("execution_trace", ""),
                        "compile_time": run_result.get("compile_time", 0.0),
                        "execution_time": run_result.get("execution_time", 0.0),
                    }
                    # Metrics are derived only from the runner's observed
                    # compilation/execution result, never inferred from a
                    # generated file or output text.
                    poc_metrics["repair_attempts"] += run_result.get("retries", 0)
                    if run_result.get("compiled"):
                        poc_metrics["compiled_pocs"] += 1
                        poc_metrics["_compile_times"].append(run_result.get("compile_time", 0.0))
                    else:
                        poc_metrics["compilation_failures"] += 1
                    if run_result.get("executed"):
                        poc_metrics["executed_pocs"] += 1
                        poc_metrics["_execution_times"].append(run_result.get("execution_time", 0.0))
                    if run_result.get("compiled") and run_result.get("executed") and not run_result.get("success"):
                        poc_metrics["execution_failures"] += 1
                    if run_result.get("success"):
                        poc_metrics["successful_exploits"] += 1
                else:
                    if poc_data.get("poc_strategy") in {"demonstration", "informational"}:
                        console.print("[dim]Demonstration PoC created; Forge execution is not required.[/dim]")
                    else:
                        console.print("[dim]Auto-run disabled. Test generated but not executed.[/dim]")
                    poc_data["execution_results"] = {
                        "success": False,
                        "compiled": poc_data.get("compiled", False),
                        "executed": False,
                        "retries": 0,
                        "compile_error": poc_data.get("compile_error", ""),
                        "runtime_error": "",
                    }
                    if poc_data.get("compiled"):
                        poc_metrics["compiled_pocs"] += 1
                        poc_metrics["_compile_times"].append(poc_data.get("compile_time", 0.0))

                # Add PoC data to the result
                poc_info["poc_data"] = poc_data
                generated_pocs.append(poc_info)
                console.print(f"[bold green]✓ Generated demonstration for {vul.get('vulnerability_type')}[/bold green]")

        # End the last stage
        performance_tracker.end_stage()
        log_findings("Merged/final findings", rechecked_vulns)
        console.print("\n[bold green]✓ Agent workflow completed[/bold green]")
        
        # Avoid printing token stats here - we'll do it in main.py as part of the comprehensive performance summary
        
        compile_times = poc_metrics.pop("_compile_times")
        execution_times = poc_metrics.pop("_execution_times")
        poc_metrics["average_compile_time"] = sum(compile_times) / len(compile_times) if compile_times else 0.0
        poc_metrics["average_execution_time"] = sum(execution_times) / len(execution_times) if execution_times else 0.0
        return {
            "rechecked_vulnerabilities": rechecked_vulns,
            "generated_pocs": generated_pocs,
            "poc_metrics": poc_metrics,
            "token_usage": token_tracker.get_usage_summary() if 'token_tracker' in locals() else None
        }
