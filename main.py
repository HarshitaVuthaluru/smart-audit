import os
import json
import argparse
import re
from collections import Counter
from pathlib import Path
from dotenv import load_dotenv
from static_analysis.parse_contract import analyze_contract
from llm_agents.agent_coordinator import AgentCoordinator
from llm_agents.config import ModelConfig
from utils.print_utils import *
from utils.token_tracker import performance_tracker


def _report_confidence(finding):
    """Return a bounded calibrated confidence without changing finding data."""
    try:
        return max(0.0, min(1.0, float(finding.get("skeptic_confidence", finding.get("confidence_score", 0)))))
    except (TypeError, ValueError):
        return 0.0


def _report_type_key(vulnerability_type):
    value = str(vulnerability_type or "unknown").lower().replace("-", "_").replace(" ", "_")
    aliases = {"selfdestruct": "dangerous_selfdestruct", "dangerous_selfdestruct": "dangerous_selfdestruct"}
    return aliases.get(value, value)


def _deduplicate_report_findings(findings):
    """Merge report duplicates while retaining the strongest available detail."""
    merged, merged_count = {}, 0
    for finding in findings:
        key = (_report_type_key(finding.get("vulnerability_type")), tuple(sorted(finding.get("affected_functions", []))))
        current = merged.get(key)
        if current is None:
            merged[key] = dict(finding)
            continue
        merged_count += 1
        winner, other = (finding, current) if _report_confidence(finding) > _report_confidence(current) else (current, finding)
        item = dict(winner)
        for field in ("reasoning", "validity_reasoning", "code_snippet"):
            if len(str(other.get(field, ""))) > len(str(item.get(field, ""))):
                item[field] = other[field]
        item["merged_findings"] = int(current.get("merged_findings", 0)) + 1
        merged[key] = item
    return list(merged.values()), merged_count


def _risk_level(finding):
    confidence = _report_confidence(finding)
    vuln_type = _report_type_key(finding.get("vulnerability_type"))
    impact = str(finding.get("impact", finding.get("severity", ""))).lower()
    exploitability = 1.0 if vuln_type in {"reentrancy", "dangerous_selfdestruct", "access_control"} else 0.7
    impact_weight = 1.0 if any(label in impact for label in ("critical", "high")) else 0.65
    score = round(100 * confidence * exploitability * impact_weight)
    level = "Critical" if score >= 75 else "High" if score >= 50 else "Medium" if score >= 25 else "Low"
    return level, score


def _report_poc_quality(poc):
    data = poc.get("poc_data", {})
    execution = data.get("execution_results", {})
    plan = poc.get("exploit_plan", {})
    steps = sum(len(plan.get(key, [])) for key in ("setup_steps", "execution_steps", "validation_steps"))
    return (int(bool(execution.get("success"))), int(bool(execution.get("executed"))), int(bool(data.get("exploit_code"))), steps)

def parse_arguments():
    """Parse command line arguments for model configuration"""
    parser = argparse.ArgumentParser(description="Smart Contract Vulnerability Analyzer")

    # Add model configuration arguments
    parser.add_argument("--analyzer-model", default="qwen2.5-coder:7b", help="Model for analyzer agent")
    parser.add_argument("--skeptic-model", default="qwen2.5-coder:7b", help="Model for skeptic agent")
    parser.add_argument("--exploiter-model", default="qwen2.5-coder:7b", help="Model for exploiter agent")
    parser.add_argument("--generator-model", default="qwen2.5-coder:7b", help="Model for generator agent")
    parser.add_argument("--context-model", default="qwen2.5-coder:7b", help="Model for context agent")
    parser.add_argument("--all-models", help="Use this model for all agents")
    parser.add_argument("--api-base", help="Base URL for OpenAI API")

    # Add contract file option
    parser.add_argument("--contract", default="VulnerableBank.sol",
                      help="Path to contract file to analyze")
    parser.add_argument("--contract-address",
                      help="Blockchain contract address to fetch and analyze")
    parser.add_argument("--network", default="ethereum",
                      help="Blockchain network (ethereum, bsc, base, arbitrum)")
    # Removed --project-dir as it's implicitly handled by fetching or direct path
    parser.add_argument("--save-separate", action="store_true",
                      help="Save separate contract files in addition to flattened file when fetching")

    # Add auto-run options
    parser.add_argument("--no-auto-run", action="store_true",
                      help="Disable automatic execution of generated PoCs")
    parser.add_argument("--max-retries", type=int, default=3,
                      help="Maximum number of fix attempts for failed tests (default: 3)")

    # Add RAG option
    parser.add_argument("--no-rag", action="store_true",
                      help="Disable Retrieval Augmented Generation for analysis")

    # Add PoC generation and report export options
    parser.add_argument("--skip-poc", action="store_true",
                      help="Skip PoC generation and stop at exploit plans")
    parser.add_argument("--export-md", action="store_true",
                      help="Export analysis report as Markdown file")
    parser.add_argument("--export-json", help="Export results to a JSON file for automated analysis")

    return parser.parse_args()

def export_results_to_html(contract_path, results):
    """Export analysis results to a beautiful HTML file and open it in the browser"""
    from datetime import datetime
    import os
    import webbrowser

    contract_name = os.path.basename(contract_path)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dir_path = "reports"
    os.makedirs(dir_path, exist_ok=True)
    output_file = os.path.join(dir_path, f"analysis_report_{contract_name}_{timestamp}.html")

    rechecked_vulns, merged_findings_count = _deduplicate_report_findings(results.get("rechecked_vulnerabilities", []))
    pocs = results.get("generated_pocs", [])
    poc_metrics = results.get("poc_metrics", {})

    # Calculate detailed statistics
    total_vulns = len(rechecked_vulns)
    true_positives = sum(1 for v in rechecked_vulns if float(v.get('skeptic_confidence', 0)) > 0.7)
    potential_false_positives = sum(1 for v in rechecked_vulns if float(v.get('skeptic_confidence', 0)) < 0.4)
    severity_distribution = Counter(_risk_level(v)[0] for v in rechecked_vulns)
    confidence_distribution = Counter("High" if _report_confidence(v) >= .8 else "Medium" if _report_confidence(v) >= .5 else "Low" for v in rechecked_vulns)
    overall_risk = round(sum(_risk_level(v)[1] for v in rechecked_vulns) / total_vulns) if total_vulns else 0
    overall_level = "Critical" if overall_risk >= 75 else "High" if overall_risk >= 50 else "Medium" if overall_risk >= 25 else "Low"
    
    generated_pocs_count = poc_metrics.get("generated_pocs", len(pocs))
    compiled_pocs_count = poc_metrics.get("compiled_pocs", 0)
    executed_pocs_count = poc_metrics.get("executed_pocs", 0)
    successful_exploits_count = poc_metrics.get("successful_exploits", 0)
    compilation_failures_count = poc_metrics.get("compilation_failures", 0)
    execution_failures_count = poc_metrics.get("execution_failures", 0)
    
    for p in (pocs if not poc_metrics else []):
        if "poc_data" in p:
            poc_data = p["poc_data"]
            exec_res = poc_data.get("execution_results", {})
            
            if exec_res.get("compiled"):
                compiled_pocs_count += 1
            else:
                compilation_failures_count += 1
                
            if exec_res.get("executed"):
                executed_pocs_count += 1
                if exec_res.get("success"):
                    successful_exploits_count += 1
                else:
                    execution_failures_count += 1

    compile_rate = (compiled_pocs_count / generated_pocs_count * 100) if generated_pocs_count else 0
    execution_rate = (successful_exploits_count / executed_pocs_count * 100) if executed_pocs_count else 0
    repairs = poc_metrics.get("repair_attempts", sum(p.get("poc_data", {}).get("execution_results", {}).get("retries", 0) for p in pocs))
    average_repairs = repairs / generated_pocs_count if generated_pocs_count else 0

    # Format vulnerabilities list for JS/HTML
    vulns_html = ""
    vulns_sidebar_html = ""
    
    for idx, vuln in enumerate(rechecked_vulns, start=1):
        vuln_type = vuln.get('vulnerability_type', 'Unknown')
        try:
            confidence = float(vuln.get('skeptic_confidence', 0))
        except (ValueError, TypeError):
            confidence = 0.0
        
        confidence_class = "conf-high" if confidence > 0.7 else "conf-medium" if confidence > 0.4 else "conf-low"
        confidence_label = f"{confidence:.2f}"
        risk_level, risk_score = _risk_level(vuln)
        
        # Sidebar item
        vulns_sidebar_html += f"""
        <div class="sidebar-item" onclick="showVulnerability({idx})">
            <span class="sidebar-title">{vuln_type}</span>
            <span class="badge {confidence_class}">Conf: {confidence_label}</span>
        </div>
        """
        
        # Details page
        reasoning = vuln.get('reasoning', 'N/A').replace('\n', '<br>')
        validity = vuln.get('validity_reasoning', '').replace('\n', '<br>')
        code_snippet = vuln.get('code_snippet', '')
        code_snippet_html = f"<pre><code class='language-solidity'>{code_snippet}</code></pre>" if code_snippet else "<p>No code snippet provided.</p>"
        
        affected_funcs = ", ".join(vuln.get('affected_functions', []))
        
        # Find matching PoC
        poc_info_html = "<p class='no-poc'>No Proof of Concept generated.</p>"
        matching = [p for p in pocs if _report_type_key(p.get("vulnerability", {}).get("vulnerability_type")) == _report_type_key(vuln_type)]
        matching_poc = max(matching, key=_report_poc_quality, default=None)
        
        if matching_poc:
            plan = matching_poc.get("exploit_plan", {})
            setup = "".join(f"<li>{s}</li>" for s in plan.get("setup_steps", []))
            execution = "".join(f"<li>{e}</li>" for e in plan.get("execution_steps", []))
            validation = "".join(f"<li>{v}</li>" for v in plan.get("validation_steps", []))
            
            plan_html = f"""
            <div class="exploit-plan">
                <h4>Exploit Plan</h4>
                {f"<h5>Setup</h5><ul>{setup}</ul>" if setup else ""}
                {f"<h5>Execution</h5><ul>{execution}</ul>" if execution else ""}
                {f"<h5>Validation</h5><ul>{validation}</ul>" if validation else ""}
            </div>
            """
            
            poc_data = matching_poc.get("poc_data", {})
            exploit_code = poc_data.get("exploit_code", "")
            code_html = f"<pre><code class='language-solidity'>{exploit_code}</code></pre>" if exploit_code else ""
            
            exec_res = poc_data.get("execution_results", {})
            success_status = exec_res.get("success")
            
            if success_status is True:
                status_html = "<span class='badge conf-high'>SUCCESS</span>"
            elif success_status is False:
                status_html = f"<span class='badge conf-low'>FAILED (Retries: {exec_res.get('retries', 0)})</span>"
            else:
                status_html = "<span class='badge conf-medium'>SKIPPED / UNTESTED</span>"
                
            compiler_diagnostics = exec_res.get("compile_error", "")
            runtime_diagnostics = exec_res.get("runtime_error", exec_res.get("error", ""))
            execution_trace = exec_res.get("execution_trace", "")
            error_html = "".join((
                f"<div class='error-box'><h5>Compiler Diagnostics</h5><pre><code>{compiler_diagnostics}</code></pre></div>" if compiler_diagnostics else "",
                f"<div class='error-box'><h5>Runtime Diagnostics</h5><pre><code>{runtime_diagnostics}</code></pre></div>" if runtime_diagnostics else "",
                f"<div class='error-box'><h5>Execution Trace</h5><pre><code>{execution_trace}</code></pre></div>" if execution_trace else "",
            ))
            
            # Extract gas usage
            gas_usage = "N/A"
            if runtime_diagnostics:
                gas_match = re.search(r"gas:\s*(\d+)", runtime_diagnostics)
                if gas_match:
                    gas_usage = gas_match.group(1)

            poc_info_html = f"""
            <div class="poc-details">
                <h4>PoC Details</h4>
                <p><strong>File:</strong> <code>{os.path.basename(poc_data.get('exploit_file', 'N/A'))}</code></p>
                <p><strong>Status:</strong> {status_html} | <strong>Compiled:</strong> {'✅' if exec_res.get('compiled') else '❌'} | <strong>Executed:</strong> {'✅' if exec_res.get('executed') else '❌'}</p>
                <p><strong>Gas Usage:</strong> {exec_res.get('gas_used', gas_usage)} | <strong>Repair Attempts:</strong> {exec_res.get('retries', 0)}</p>
                {error_html}
                {plan_html}
                {f"<h5>Exploit Code</h5>{code_html}" if exploit_code else ""}
            </div>
            """
            
        vulns_html += f"""
        <div id="vuln-details-{idx}" class="vuln-details-card" style="display: none;">
            <div class="details-header">
                <h3>{vuln_type}</h3>
                <span class="badge {confidence_class}">Confidence: {confidence_label}</span>
            </div>
            <div class="details-body">
                <div class="meta-section">
                    <p><strong>Affected Functions:</strong> {affected_funcs or 'None'}</p>
                    <p><strong>Risk:</strong> {risk_level} ({risk_score}/100) | <strong>Calibrated Confidence:</strong> {confidence_label}</p>
                    <p><strong>Skeptic Verdict:</strong> {vuln.get('skeptic_status', 'N/A')} | <strong>Merged Findings:</strong> {vuln.get('merged_findings', 0)}</p>
                    <p><strong>Deterministic Evidence:</strong> {vuln.get('exploitation_scenario', 'N/A')}</p>
                </div>
                
                <div class="tabs-container">
                    <div class="tab-buttons">
                        <button class="tab-btn active" onclick="switchDetailTab(event, 'analysis-{idx}')">Analysis</button>
                        <button class="tab-btn" onclick="switchDetailTab(event, 'poc-{idx}')">Proof of Concept</button>
                    </div>
                    
                    <div id="analysis-{idx}" class="detail-tab-content">
                        <h4>Reasoning</h4>
                        <div class="reasoning-text">{reasoning}</div>
                        
                        {f"<h4>Validation Reasoning</h4><div class='reasoning-text'>{validity}</div>" if validity else ""}
                        
                        <h4>Code Snippet</h4>
                        {code_snippet_html}
                    </div>
                    
                    <div id="poc-{idx}" class="detail-tab-content" style="display: none;">
                        {poc_info_html}
                    </div>
                </div>
            </div>
        </div>
        """

    # Recommendation list
    found_vuln_types = {v.get('vulnerability_type', '').lower() for v in rechecked_vulns}
    recs_html = ""
    if any('reentrancy' in vt for vt in found_vuln_types):
        recs_html += "<li><strong>Reentrancy:</strong> Use checks-effects-interactions pattern, ReentrancyGuard.</li>"
    if any(term in vt for vt in found_vuln_types for term in ['overflow', 'underflow', 'arithmetic']):
        recs_html += "<li><strong>Arithmetic:</strong> Use Solidity 0.8+ or SafeMath.</li>"
    if any(term in vt for vt in found_vuln_types for term in ['access', 'authorization', 'permission']):
        recs_html += "<li><strong>Access Control:</strong> Use modifiers (e.g. <code>onlyOwner</code>), check roles properly.</li>"
    if any(term in vt for vt in found_vuln_types for term in ['oracle', 'price']):
        recs_html += "<li><strong>Oracle Manipulation:</strong> Use TWAP, multiple sources (e.g., Chainlink).</li>"
    if any('unchecked' in vt for vt in found_vuln_types):
        recs_html += "<li><strong>Unchecked Returns:</strong> Check return values of external calls.</li>"
    recs_html += "<li><strong>General:</strong> Conduct thorough testing and consider professional audits.</li>"
    severity_html = "".join(f"<div class='bar-row'><span>{level}</span><div class='bar'><i style='width:{(count / max(total_vulns, 1)) * 100:.0f}%'></i></div><b>{count}</b></div>" for level, count in (('Critical', severity_distribution['Critical']), ('High', severity_distribution['High']), ('Medium', severity_distribution['Medium']), ('Low', severity_distribution['Low'])))
    confidence_html = "".join(f"<div class='bar-row'><span>{level}</span><div class='bar'><i style='width:{(count / max(total_vulns, 1)) * 100:.0f}%'></i></div><b>{count}</b></div>" for level, count in (('High', confidence_distribution['High']), ('Medium', confidence_distribution['Medium']), ('Low', confidence_distribution['Low'])))
    top_risks = sorted(rechecked_vulns, key=lambda finding: _risk_level(finding)[1], reverse=True)[:5]
    top_risks_html = "".join(f"<li>{finding.get('vulnerability_type', 'Unknown')} — {_risk_level(finding)[0]} ({_risk_level(finding)[1]}/100)</li>" for finding in top_risks) or "<li>No findings identified.</li>"
    performance = performance_tracker.get_performance_summary()
    token_total = performance['token_usage']['total']['total_tokens']
    runtime = performance['run_info']['total_time_seconds']
    agent_times_html = "".join(
        f"<li>{stage}: {seconds:.2f}s</li>" for stage, seconds in performance['time_metrics']['stage_times'].items()
    ) or "<li>No completed stages recorded.</li>"
    tokens_per_vulnerability = token_total / total_vulns if total_vulns else 0
    time_per_vulnerability = runtime / total_vulns if total_vulns else 0

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smart Contract Vulnerability Analysis Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css">
    <style>
        :root {{
            --bg-main: #0f172a;
            --bg-card: #1e293b;
            --bg-accent: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --primary: #4f46e5;
            --primary-gradient: linear-gradient(135deg, #4f46e5 0%, #3b82f6 100%);
            --border: #475569;
            --high-conf: #ef4444;
            --med-conf: #f59e0b;
            --low-conf: #10b981;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Inter', sans-serif; background-color: var(--bg-main); color: var(--text-main); line-height: 1.6; }}
        header {{ background: var(--primary-gradient); padding: 2rem; color: white; margin-bottom: 2rem; }}
        .header-container {{ max-width: 1400px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; }}
        .main-container {{ max-width: 1400px; margin: 0 auto; padding: 0 1.5rem; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .stat-card {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 0.5rem; padding: 1rem; }}
        .stat-label {{ font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase; }}
        .stat-value {{ font-size: 1.4rem; font-weight: 700; }}
        .report-layout {{ display: grid; grid-template-columns: 300px 1fr; gap: 2rem; }}
        .sidebar {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 0.5rem; padding: 1rem; }}
        .sidebar-item {{ padding: 0.75rem; background: var(--bg-accent); border-radius: 0.4rem; cursor: pointer; margin-bottom: 0.5rem; display: flex; justify-content: space-between; font-size: 0.85rem; }}
        .sidebar-item.active {{ background: var(--primary); }}
        .badge {{ font-size: 0.65rem; padding: 0.2rem 0.4rem; border-radius: 0.2rem; }}
        .conf-high {{ background: var(--high-conf); }}
        .conf-medium {{ background: var(--med-conf); color: black; }}
        .conf-low {{ background: var(--low-conf); }}
        .vuln-details-card {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 0.5rem; padding: 1.5rem; }}
        .tab-buttons {{ display: flex; border-bottom: 1px solid var(--border); margin-bottom: 1rem; }}
        .tab-btn {{ background: none; border: none; color: var(--text-muted); padding: 0.5rem 1rem; cursor: pointer; }}
        .tab-btn.active {{ color: white; border-bottom: 2px solid var(--primary); }}
        pre {{ background: #0b0f19 !important; padding: 1rem !important; border-radius: 0.4rem; overflow: auto; }}
        .error-box {{ background: #1e293b; padding: 1rem; border-radius: 0.4rem; margin-top: 1rem; }}
        .summary-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:1rem; margin-bottom:2rem; }}
        .summary-card {{ background:var(--bg-card); border:1px solid var(--border); border-radius:.5rem; padding:1rem; }}
        .bar-row {{ display:grid; grid-template-columns:70px 1fr 24px; gap:.5rem; align-items:center; margin:.45rem 0; font-size:.85rem; }}
        .bar {{ height:10px; background:var(--bg-accent); border-radius:99px; overflow:hidden; }}
        .bar i {{ display:block; height:100%; background:var(--primary); }}
    </style>
</head>
<body>
    <header>
        <div class="header-container">
            <div><h1>VLD Analysis Report</h1><p>{contract_name} | {timestamp}</p></div>
        </div>
    </header>
    <main class="main-container">
        <div class="stats-grid">
            <div class="stat-card"><div class="stat-label">Overall Risk</div><div class="stat-value">{overall_level} {overall_risk}/100</div></div>
            <div class="stat-card"><div class="stat-label">Total</div><div class="stat-value">{total_vulns}</div></div>
            <div class="stat-card"><div class="stat-label">True Positives</div><div class="stat-value">{true_positives}</div></div>
            <div class="stat-card"><div class="stat-label">Potential False Positives</div><div class="stat-value">{potential_false_positives}</div></div>
            <div class="stat-card"><div class="stat-label">Generated PoCs</div><div class="stat-value">{generated_pocs_count}</div></div>
            <div class="stat-card"><div class="stat-label">Compiled</div><div class="stat-value">{compiled_pocs_count}</div></div>
            <div class="stat-card"><div class="stat-label">Executed</div><div class="stat-value">{executed_pocs_count}</div></div>
            <div class="stat-card"><div class="stat-label">Successful</div><div class="stat-value" style="color:var(--low-conf)">{successful_exploits_count}</div></div>
        </div>
        <div class="summary-grid">
            <section class="summary-card"><h3>Executive Summary</h3><p>{total_vulns} consolidated finding(s), {merged_findings_count} duplicate(s) merged. Overall risk is <strong>{overall_level}</strong>.</p><h4>Top Risks</h4><ol>{top_risks_html}</ol></section>
            <section class="summary-card"><h3>Severity Distribution</h3>{severity_html}<h3>Confidence Distribution</h3>{confidence_html}</section>
            <section class="summary-card"><h3>Performance Dashboard</h3><p>Tokens: {token_total:,}</p><p>Runtime: {runtime:.2f}s</p><p>Tokens/finding: {tokens_per_vulnerability:.1f}; time/finding: {time_per_vulnerability:.2f}s</p><p>Average repairs: {average_repairs:.2f}</p><p>Compile success: {compile_rate:.1f}%</p><p>Execution success: {execution_rate:.1f}%</p><p>Compilation failures: {compilation_failures_count}; execution failures: {execution_failures_count}</p><h4>Agent Timeline</h4><ul>{agent_times_html}</ul></section>
            <section class="summary-card"><h3>Recommended Fixes</h3><ul>{recs_html}</ul><p><strong>Audit conclusion:</strong> Address Critical/High findings first, then re-run generated PoCs and regression tests.</p></section>
        </div>
        <div class="report-layout">
            <div class="sidebar"><h3>Findings</h3><div class="sidebar-list">{vulns_sidebar_html}</div></div>
            <div class="content-panel">{vulns_html}</div>
        </div>
    </main>
    <script>
        function showVulnerability(idx) {{
            document.querySelectorAll('.vuln-details-card').forEach(c => c.style.display = 'none');
            document.querySelectorAll('.sidebar-item').forEach(i => i.classList.remove('active'));
            document.getElementById('vuln-details-' + idx).style.display = 'block';
            document.querySelectorAll('.sidebar-list .sidebar-item')[idx-1].classList.add('active');
        }}
        function switchDetailTab(e, id) {{
            const p = e.target.parentElement;
            p.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            const c = p.parentElement;
            c.querySelectorAll('.detail-tab-content').forEach(tc => tc.style.display = 'none');
            document.getElementById(id).style.display = 'block';
        }}
        if ({total_vulns} > 0) showVulnerability(1);
    </script>
</body>
</html>"""

    try:
        with open(output_file, "w", encoding='utf-8') as f:
            f.write(html_content)
        print_success(f"Report: {output_file}")
        webbrowser.open("file://" + os.path.abspath(output_file))
    except Exception as e:
        print_error(f"HTML Export failed: {e}")

def main():
    print_header("Smart Contract Vulnerability Analyzer")
    performance_tracker.reset()
    performance_tracker.start_stage("initialization")
    args = parse_arguments()

    run_config = {
        "analyzer_model": args.analyzer_model,
        "skeptic_model": args.skeptic_model,
        "exploiter_model": args.exploiter_model,
        "generator_model": args.generator_model,
        "context_model": args.context_model,
        "all_models": args.all_models,
        "use_rag": not args.no_rag,
        "skip_poc": args.skip_poc,
        "auto_run": not args.no_auto_run
    }
    performance_tracker.set_run_config(run_config)

    try:
        load_dotenv()
        print_success("Environment loaded")
    except Exception as e:
        print_error(f"Env failed: {e}")
        return

    if args.all_models:
        model_config = ModelConfig(
            analyzer_model=args.all_models,
            skeptic_model=args.all_models,
            exploiter_model=args.all_models,
            generator_model=args.all_models,
            context_model=args.all_models,
            base_url=args.api_base,
            skip_poc_generation=args.skip_poc,
            export_markdown=args.export_md
        )
    else:
        model_config = ModelConfig(
            analyzer_model=args.analyzer_model,
            skeptic_model=args.skeptic_model,
            exploiter_model=args.exploiter_model,
            generator_model=args.generator_model,
            context_model=args.context_model,
            base_url=args.api_base,
            skip_poc_generation=args.skip_poc,
            export_markdown=args.export_md
        )

    filepath = args.contract
    contracts_dir = None
    target_filename = os.path.basename(filepath)

    if args.contract_address:
        from utils.source_code_fetcher import fetch_and_flatten_contract
        uploads_dir = os.path.join(os.getcwd(), "uploads")
        os.makedirs(uploads_dir, exist_ok=True)
        output_file = os.path.join(uploads_dir, f"{args.contract_address}_{args.network}.sol")
        try:
            fetch_and_flatten_contract(network=args.network, contract_address=args.contract_address, output_file=output_file, flatten=True)
            filepath = output_file
            target_filename = os.path.basename(filepath)
        except Exception as e:
            print_error(f"Fetch failed: {e}")
            return

    # Copy to exploit/src
    try:
        import shutil
        os.makedirs("exploit/src", exist_ok=True)
        shutil.copy2(filepath, os.path.join("exploit", "src", target_filename))
    except Exception as e:
        print_warning(f"Copy failed: {e}")

    performance_tracker.start_stage("static_analysis")
    try:
        function_details, call_graph, detector_results = analyze_contract(filepath)
    except Exception as e:
        print_error(f"Slither failed: {e}")
        return

    with open(filepath, "r", encoding="utf-8") as f:
        source_code = f.read()
    # The tracker cannot infer the input from downstream dictionaries; record
    # the concrete Solidity file once it has been successfully read.
    performance_tracker.log_code_analysis([filepath])

    contract_info = {
        "function_details": function_details,
        "call_graph": call_graph,
        "source_code": source_code,
        "detector_results": detector_results,
        "target_contract": {"path": target_filename, "filename": target_filename},
    }

    performance_tracker.start_stage("llm_analysis")
    coordinator = AgentCoordinator(model_config=model_config, use_rag=not args.no_rag)
    auto_run_config = {"auto_run": not args.no_auto_run, "max_retries": args.max_retries}

    try:
        results = coordinator.analyze_contract(contract_info, auto_run_config=auto_run_config)
    except Exception as e:
        print_error(f"Analysis failed: {e}")
        return

    performance_tracker.start_stage("export")
    if args.export_json:
        try:
            with open(args.export_json, "w", encoding="utf-8") as handle:
                json.dump(results, handle, indent=2, default=str)
            print_success(f"JSON results: {args.export_json}")
        except OSError as exc:
            print_warning(f"JSON export failed: {exc}")
    export_results_to_html(filepath, results)
    performance_tracker.end_stage()
    performance_tracker.print_summary()

if __name__ == "__main__":
    main()
