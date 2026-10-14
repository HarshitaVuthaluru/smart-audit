"""
Phase 6 Evaluation Runner
Run the complete production pipeline on each out-of-sample contract and measure metrics.
"""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from scratch.phase6_ground_truth import PHASE6_GROUND_TRUTH


def canonical_type(vtype: str) -> str:
    import re as _re
    key = str(vtype or "").lower().replace("-", "_").replace(" ", "_").strip("()")
    key = _re.sub(r"\s*\(.*?\)", "", key).strip("_").replace("__", "_")
    aliases = {
        "dangerous_selfdestruct": "access_control",
        "selfdestruct": "access_control",
        "destroy": "access_control",
        "unauthorized_transfer": "access_control",
        "unauthorized_transfers": "access_control",
        "unauthenticated_destruction": "access_control",
        "access_control": "access_control",
        "access_control_high_priority": "access_control",
        "timestamp_dependence": "bad_randomness",
        "timestamp": "bad_randomness",
        "randomness": "bad_randomness",
        "bad_randomness": "bad_randomness",
        "reentrancy": "reentrancy",
        "unchecked_low_level_calls": "unchecked_low_level_calls",
        "unchecked_call": "unchecked_low_level_calls",
        "unchecked_ll_calls": "unchecked_low_level_calls",
        "business_logic": "business_logic",
        "no_slippage_limit_check": "no_slippage_limit_check",
        "arithmetic": "arithmetic",
        "integer_overflow": "arithmetic",
        "integer_underflow": "arithmetic",
        "overflow": "arithmetic",
        "underflow": "arithmetic",
        "denial_of_service": "denial_of_service",
        "front_running": "front_running",
    }
    return aliases.get(key, key)


def func_name_base(fn: str) -> str:
    fn = str(fn or "").strip()
    return fn.split("(")[0].split(".")[-1]


def run_contract(contract_path: str, output_file: str) -> dict:
    cmd = [
        sys.executable, "main.py",
        "--contract", contract_path,
        "--skip-poc",
        "--export-json", output_file
    ]
    proc = subprocess.run(
        cmd, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
        cwd="C:/Project/VLD"
    )
    return proc


def deduplicate_findings(findings, contract_name):
    merged = {}
    for f in findings:
        ctype = canonical_type(f.get("vulnerability_type"))
        funcs = tuple(sorted([func_name_base(x) for x in f.get("affected_functions", [])]))
        key = (contract_name, ctype, funcs)
        conf = float(f.get("skeptic_confidence", f.get("confidence_score", 0)) or 0)
        if key not in merged or conf > merged[key]["skeptic_confidence"]:
            merged[key] = {
                "contract": contract_name,
                "vulnerability_type": ctype,
                "original_type": f.get("vulnerability_type"),
                "affected_functions": f.get("affected_functions", []),
                "skeptic_confidence": conf,
                "skeptic_status": f.get("skeptic_status", "UNKNOWN"),
                "evidence_source": f.get("evidence_source", "unknown"),
                "reasoning": f.get("validity_reasoning", f.get("reasoning", ""))
            }
    return list(merged.values())


def evaluate():
    project_root = Path("C:/Project/VLD")
    scratch_dir = project_root / "scratch" / "phase6_results"
    scratch_dir.mkdir(parents=True, exist_ok=True)

    all_findings = []
    contract_results = []

    for entry in PHASE6_GROUND_TRUTH:
        contract_name = entry["contract_name"]
        contract_path = str(project_root / entry["path"])
        output_file = str(scratch_dir / f"result_{contract_name}.json")

        print(f"\nRunning: {contract_name} {'[IN-RAG]' if entry['in_rag'] else '[OUT-OF-RAG]'}", flush=True)
        proc = run_contract(contract_path, output_file)

        findings = []
        if Path(output_file).exists():
            data = json.loads(Path(output_file).read_text(encoding="utf-8"))
            raw = data.get("rechecked_vulnerabilities", [])
            findings = deduplicate_findings(raw, contract_name)
            print(f"  => {len(findings)} findings", flush=True)
        else:
            print(f"  => ERROR: no output file produced", flush=True)

        all_findings.extend(findings)

        # Per-contract GT matching
        gt_items = entry["functions_gt"]
        for fn_base, expected_cat in gt_items:
            matching_by_func = [
                f for f in findings
                if fn_base in [func_name_base(x) for x in f["affected_functions"]]
            ]
            matching_exact = [
                f for f in matching_by_func
                if f["vulnerability_type"] == expected_cat
            ]
            localized = len(matching_by_func) > 0
            correct_cat = len(matching_exact) > 0

            if correct_cat:
                status = "TP"
            elif localized:
                status = "FN (wrong_cat)"
            else:
                status = "FN (missed)"

            actual_cat = matching_exact[0]["vulnerability_type"] if matching_exact else (
                matching_by_func[0]["vulnerability_type"] if matching_by_func else "NOT_DETECTED"
            )
            actual_fn = matching_by_func[0]["affected_functions"] if matching_by_func else []
            skeptic_v = matching_exact[0]["skeptic_status"] if matching_exact else (
                matching_by_func[0]["skeptic_status"] if matching_by_func else "N/A"
            )

            contract_results.append({
                "contract": contract_name,
                "in_rag": entry["in_rag"],
                "expected_function": fn_base,
                "expected_category": expected_cat,
                "evidence": entry["evidence"],
                "localized": localized,
                "correct_category": correct_cat,
                "status": status,
                "actual_category": actual_cat,
                "actual_functions": actual_fn,
                "skeptic_verdict": skeptic_v,
                "source_grounded": "YES" if matching_exact and matching_exact[0].get("evidence_source") != "unknown" else "NO"
            })
            print(f"  GT: {fn_base}/{expected_cat} => {status}", flush=True)

    # FP calculation: findings not matched to any GT
    gt_pairs = set()
    for entry in PHASE6_GROUND_TRUTH:
        for fn_base, cat in entry["functions_gt"]:
            gt_pairs.add((entry["contract_name"], fn_base, cat))

    fps = []
    for f in all_findings:
        contract = f["contract"]
        ctype = f["vulnerability_type"]
        funcs = [func_name_base(x) for x in f["affected_functions"]]
        is_tp = any((contract, fn, ctype) in gt_pairs for fn in funcs)
        if not is_tp:
            fps.append(f)

    tp = sum(1 for r in contract_results if r["status"] == "TP")
    fn = sum(1 for r in contract_results if r["status"] != "TP")
    fp = len(fps)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    loc_count = sum(1 for r in contract_results if r["localized"])
    cat_count = sum(1 for r in contract_results if r["correct_category"])
    loc_acc = loc_count / len(contract_results) if contract_results else 0.0
    cat_acc = cat_count / loc_count if loc_count > 0 else 0.0

    print("\n" + "="*60)
    print("PHASE 6 EVALUATION SUMMARY")
    print("="*60)
    print(f"Contracts evaluated: {len(PHASE6_GROUND_TRUTH)}")
    print(f"Expected findings:   {len(contract_results)}")
    print(f"Total findings emitted: {len(all_findings)}")
    print(f"TP: {tp}")
    print(f"FN: {fn}")
    print(f"FP: {fp}")
    print(f"Precision: {precision*100:.1f}%")
    print(f"Recall:    {recall*100:.1f}%")
    print(f"F1:        {f1*100:.1f}%")
    print(f"Category Accuracy:      {cat_acc*100:.1f}%")
    print(f"Function Localization:  {loc_acc*100:.1f}%")

    print("\n--- PER-CONTRACT RESULTS ---")
    for r in contract_results:
        print(f"  {r['contract']} | {r['expected_function']} | {r['expected_category']} | {r['status']} | actual={r['actual_category']} | fn={r['actual_functions']} | skeptic={r['skeptic_verdict']}")

    print("\n--- FALSE POSITIVES ---")
    for f in fps:
        print(f"  {f['contract']} | {f['affected_functions']} | {f['vulnerability_type']}")

    # Category breakdown
    print("\n--- CATEGORY BREAKDOWN ---")
    cats = {}
    for r in contract_results:
        cat = r["expected_category"]
        if cat not in cats:
            cats[cat] = {"expected": 0, "tp": 0, "fn": 0}
        cats[cat]["expected"] += 1
        if r["status"] == "TP":
            cats[cat]["tp"] += 1
        else:
            cats[cat]["fn"] += 1

    # Count FPs by category
    fp_cats = {}
    for f in fps:
        cat = f["vulnerability_type"]
        fp_cats[cat] = fp_cats.get(cat, 0) + 1

    print(f"{'Category':<30} {'Expected':>8} {'TP':>4} {'FN':>4} {'FP':>4} {'Precision':>10} {'Recall':>8} {'F1':>6}")
    print("-" * 80)
    for cat, metrics in cats.items():
        cat_tp = metrics["tp"]
        cat_fn = metrics["fn"]
        cat_fp = fp_cats.get(cat, 0)
        cat_prec = cat_tp / (cat_tp + cat_fp) if (cat_tp + cat_fp) > 0 else 0.0
        cat_rec = cat_tp / (cat_tp + cat_fn) if (cat_tp + cat_fn) > 0 else 0.0
        cat_f1 = (2 * cat_prec * cat_rec / (cat_prec + cat_rec)) if (cat_prec + cat_rec) > 0 else 0.0
        print(f"  {cat:<28} {metrics['expected']:>8} {cat_tp:>4} {cat_fn:>4} {cat_fp:>4} {cat_prec*100:>9.1f}% {cat_rec*100:>7.1f}% {cat_f1*100:>5.1f}%")

    # Save summary
    summary = {
        "contracts_evaluated": len(PHASE6_GROUND_TRUTH),
        "total_expected_findings": len(contract_results),
        "total_findings_emitted": len(all_findings),
        "tp": tp, "fn": fn, "fp": fp,
        "precision": precision, "recall": recall, "f1": f1,
        "category_accuracy": cat_acc, "function_localization": loc_acc,
        "per_contract": contract_results,
        "false_positives": fps,
        "category_breakdown": cats
    }
    (scratch_dir / "phase6_summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    print("\nSaved: scratch/phase6_results/phase6_summary.json", flush=True)


if __name__ == "__main__":
    evaluate()
