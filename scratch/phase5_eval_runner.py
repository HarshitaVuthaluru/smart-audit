"""
Phase 5 Regression Evaluator
Verifies that Phase 5 100% metrics remain preserved.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# Exact 16 Ground Truth Vulnerabilities from Phase 5 Baseline
PHASE5_GROUND_TRUTH = [
    {
        "contract": "Lottery.sol",
        "path": "Testing Sol contracts/Lottery.sol",
        "gt": [
            ("random", "bad_randomness")
        ]
    },
    {
        "contract": "Mixed.sol",
        "path": "Testing Sol contracts/Mixed.sol",
        "gt": [
            ("withdraw", "reentrancy"),
            ("transferOwnership", "access_control"),
            ("destroy", "access_control"),
            ("random", "bad_randomness")
        ]
    },
    {
        "contract": "OwnershipBug.sol",
        "path": "Testing Sol contracts/OwnershipBug.sol",
        "gt": [
            ("transferOwnership", "access_control"),
            ("destroy", "access_control")
        ]
    },
    {
        "contract": "ReentrancyVault.sol",
        "path": "Testing Sol contracts/ReentrancyVault.sol",
        "gt": [
            ("withdraw", "reentrancy")
        ]
    },
    {
        "contract": "RewardPool.sol",
        "path": "Testing Sol contracts/RewardPool.sol",
        "gt": [
            ("addReward", "access_control")
        ]
    },
    {
        "contract": "VulnerableBank.sol",
        "path": "Testing Sol contracts/VulnerableBank.sol",
        "gt": [
            ("withdraw", "reentrancy"),
            ("transferOwnership", "access_control"),
            ("emergencyWithdraw", "access_control"),
            ("setBalance", "access_control"),
            ("destroy", "access_control"),
            ("random", "bad_randomness"),
            ("unsafeSend", "unchecked_low_level_calls")
        ]
    }
]

def canonical_type(vtype: str) -> str:
    key = str(vtype or "").lower().replace("-", "_").replace(" ", "_").strip("()")
    # Strip common LLM qualifiers like "(high priority)", "(critical)", etc.
    key = re.sub(r"\s*\(.*?\)", "", key).strip("_").replace("__", "_")
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
        "arithmetic": "arithmetic",
        "integer_overflow": "arithmetic",
        "integer_underflow": "arithmetic",
        "overflow": "arithmetic",
        "underflow": "arithmetic",
    }
    return aliases.get(key, key)

def func_name_base(fn: str) -> str:
    return str(fn or "").strip().split("(")[0].split(".")[-1]

def evaluate_phase5():
    project_root = Path("C:/Project/VLD")
    scratch_dir = project_root / "scratch" / "phase5_results"
    scratch_dir.mkdir(parents=True, exist_ok=True)

    all_findings = []
    contract_results = []

    for entry in PHASE5_GROUND_TRUTH:
        contract_name = entry["contract"]
        contract_path = str(project_root / entry["path"])
        output_file = str(scratch_dir / f"result_{contract_name}.json")

        print(f"\nRunning Phase 5 Regression: {contract_name}", flush=True)
        cmd = [
            sys.executable, "main.py",
            "--contract", contract_path,
            "--skip-poc",
            "--export-json", output_file
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=str(project_root))

        findings = []
        if Path(output_file).exists():
            data = json.loads(Path(output_file).read_text(encoding="utf-8"))
            raw = data.get("rechecked_vulnerabilities", [])
            for f in raw:
                ctype = canonical_type(f.get("vulnerability_type"))
                funcs = [func_name_base(x) for x in f.get("affected_functions", [])]
                findings.append({
                    "contract": contract_name,
                    "vulnerability_type": ctype,
                    "affected_functions": funcs,
                    "skeptic_confidence": float(f.get("skeptic_confidence", 0) or 0),
                    "skeptic_status": f.get("skeptic_status")
                })
            print(f"  => {len(findings)} findings emitted", flush=True)
        else:
            print(f"  => ERROR: No output generated for {contract_name}", flush=True)

        all_findings.extend(findings)

        for fn_base, expected_cat in entry["gt"]:
            matching_by_func = [
                f for f in findings
                if fn_base in f["affected_functions"]
            ]
            matching_exact = [
                f for f in matching_by_func
                if f["vulnerability_type"] == expected_cat
            ]
            localized = len(matching_by_func) > 0
            correct_cat = len(matching_exact) > 0

            status = "TP" if correct_cat else ("FN (wrong_cat)" if localized else "FN (missed)")
            contract_results.append({
                "contract": contract_name,
                "expected_function": fn_base,
                "expected_category": expected_cat,
                "status": status,
                "localized": localized,
                "correct_category": correct_cat
            })
            print(f"  GT: {fn_base}/{expected_cat} => {status}", flush=True)

    gt_pairs = set()
    for entry in PHASE5_GROUND_TRUTH:
        for fn_base, cat in entry["gt"]:
            gt_pairs.add((entry["contract"], fn_base, cat))

    fps = []
    for f in all_findings:
        is_tp = any((f["contract"], fn, f["vulnerability_type"]) in gt_pairs for fn in f["affected_functions"])
        if not is_tp:
            fps.append(f)

    tp = sum(1 for r in contract_results if r["status"] == "TP")
    fn = sum(1 for r in contract_results if r["status"] != "TP")
    fp = len(fps)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    print("\n" + "="*60)
    print("PHASE 5 REGRESSION SUMMARY")
    print("="*60)
    print(f"Contracts evaluated: {len(PHASE5_GROUND_TRUTH)}")
    print(f"Expected findings:   {len(contract_results)}")
    print(f"TP: {tp}")
    print(f"FN: {fn}")
    print(f"FP: {fp}")
    print(f"Precision: {precision*100:.1f}%")
    print(f"Recall:    {recall*100:.1f}%")
    print(f"F1:        {f1*100:.1f}%")

    if tp == 16 and fn == 0 and fp == 0:
        print("\nSUCCESS: Phase 5 baseline 100% metrics PRESERVED!")
    else:
        print("\nREGRESSION: Phase 5 baseline degraded!")

if __name__ == "__main__":
    evaluate_phase5()
