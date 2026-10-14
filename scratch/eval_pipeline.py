import json
import subprocess
import sys
from pathlib import Path

GROUND_TRUTH = [
    ("Lottery.sol", "random()", "bad_randomness"),
    ("Mixed.sol", "withdraw()", "reentrancy"),
    ("Mixed.sol", "transferOwnership(address)", "access_control"),
    ("Mixed.sol", "destroy()", "access_control"),
    ("Mixed.sol", "random()", "bad_randomness"),
    ("OwnershipBug.sol", "transferOwnership(address)", "access_control"),
    ("OwnershipBug.sol", "destroy()", "access_control"),
    ("ReentrancyVault.sol", "withdraw(uint256)", "reentrancy"),
    ("RewardPool.sol", "addReward(uint256)", "access_control"),
    ("VulnerableBank.sol", "withdraw(uint256)", "reentrancy"),
    ("VulnerableBank.sol", "transferOwnership(address)", "access_control"),
    ("VulnerableBank.sol", "emergencyWithdraw()", "access_control"),
    ("VulnerableBank.sol", "setBalance(address,uint256)", "access_control"),
    ("VulnerableBank.sol", "destroy()", "access_control"),
    ("VulnerableBank.sol", "random()", "bad_randomness"),
    ("VulnerableBank.sol", "unsafeSend(address,uint256)", "unchecked_low_level_calls"),
]

CONTRACTS = [
    "Lottery.sol",
    "Mixed.sol",
    "OwnershipBug.sol",
    "ReentrancyVault.sol",
    "RewardPool.sol",
    "VulnerableBank.sol",
]

def canonical_type(vtype: str) -> str:
    aliases = {
        "dangerous_selfdestruct": "access_control",
        "selfdestruct": "access_control",
        "timestamp_dependence": "bad_randomness",
        "bad_randomness": "bad_randomness",
        "reentrancy": "reentrancy",
        "access_control": "access_control",
        "unchecked_low_level_calls": "unchecked_low_level_calls",
        "business_logic": "business_logic",
        "no_slippage_limit_check": "no_slippage_limit_check",
    }
    key = str(vtype or "").lower().replace("-", "_").replace(" ", "_")
    return aliases.get(key, key)

def func_name_base(fn: str) -> str:
    fn = str(fn or "").strip()
    return fn.split("(")[0].split(".")[-1]

def run_evaluation():
    project_root = Path("C:/Project/VLD")
    contracts_dir = project_root / "Testing Sol contracts"
    scratch_dir = project_root / "scratch"
    scratch_dir.mkdir(exist_ok=True)

    all_findings = []

    for contract_name in CONTRACTS:
        contract_path = contracts_dir / contract_name
        output_file = scratch_dir / f"result_{contract_name}.json"
        
        print(f"Running pipeline on {contract_name}...", flush=True)
        cmd = [
            sys.executable, "main.py",
            "--contract", str(contract_path),
            "--skip-poc",
            "--export-json", str(output_file)
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(project_root)
        )
        if proc.returncode != 0:
            print(f"Error running {contract_name}: {proc.stderr}", flush=True)
            continue

        if output_file.exists():
            data = json.loads(output_file.read_text(encoding="utf-8"))
            findings = data.get("rechecked_vulnerabilities", [])
            print(f"Contract {contract_name} finished with {len(findings)} findings.", flush=True)
            for f in findings:
                all_findings.append({
                    "contract": contract_name,
                    "vulnerability_type": canonical_type(f.get("vulnerability_type")),
                    "original_type": f.get("vulnerability_type"),
                    "affected_functions": f.get("affected_functions", []),
                    "skeptic_confidence": f.get("skeptic_confidence", 0),
                    "reasoning": f.get("validity_reasoning", f.get("reasoning", ""))
                })

    print("\n================ DETECTED FINDINGS ================", flush=True)
    for f in all_findings:
        print(f"{f['contract']} | {f['affected_functions']} | {f['vulnerability_type']} (orig: {f['original_type']}) | conf: {f['skeptic_confidence']}", flush=True)

    # Ground truth matching
    gt_matched = [False] * len(GROUND_TRUTH)
    finding_matched = [False] * len(all_findings)

    for f_idx, f in enumerate(all_findings):
        f_contract = f["contract"]
        f_type = f["vulnerability_type"]
        f_funcs = [func_name_base(x) for x in f["affected_functions"]]

        for gt_idx, (gt_contract, gt_func, gt_type) in enumerate(GROUND_TRUTH):
            if gt_matched[gt_idx]:
                continue
            gt_func_base = func_name_base(gt_func)
            
            if f_contract == gt_contract and gt_func_base in f_funcs:
                if f_type == gt_type:
                    gt_matched[gt_idx] = True
                    finding_matched[f_idx] = True
                    break

    tp = sum(gt_matched)
    fn = len(GROUND_TRUTH) - tp
    fp = sum(not m for m in finding_matched)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    loc_count = 0
    cat_count = 0
    for gt_contract, gt_func, gt_type in GROUND_TRUTH:
        gt_func_base = func_name_base(gt_func)
        matching_funcs = [f for f in all_findings if f["contract"] == gt_contract and gt_func_base in [func_name_base(x) for x in f["affected_functions"]]]
        if matching_funcs:
            loc_count += 1
            if any(f["vulnerability_type"] == gt_type for f in matching_funcs):
                cat_count += 1

    loc_acc = loc_count / len(GROUND_TRUTH) if GROUND_TRUTH else 0.0
    cat_acc = cat_count / loc_count if loc_count > 0 else 0.0

    print("\n================ EVALUATION SUMMARY ================", flush=True)
    print(f"TP: {tp}", flush=True)
    print(f"FN: {fn}", flush=True)
    print(f"FP: {fp}", flush=True)
    print(f"Precision: {precision*100:.1f}%", flush=True)
    print(f"Recall: {recall*100:.1f}%", flush=True)
    print(f"F1: {f1*100:.1f}%", flush=True)
    print(f"Category Accuracy: {cat_acc*100:.1f}%", flush=True)
    print(f"Function Localization: {loc_acc*100:.1f}%", flush=True)

    print("\nUnmatched Ground Truth (FN):", flush=True)
    for idx, (gt_c, gt_f, gt_t) in enumerate(GROUND_TRUTH):
        if not gt_matched[idx]:
            print(f"  - {gt_c} | {gt_f} | {gt_t}", flush=True)

    print("\nUnmatched Findings (FP):", flush=True)
    for idx, f in enumerate(all_findings):
        if not finding_matched[idx]:
            print(f"  - {f['contract']} | {f['affected_functions']} | {f['vulnerability_type']}", flush=True)

    results_summary = {
        "tp": tp, "fn": fn, "fp": fp,
        "precision": precision, "recall": recall, "f1": f1,
        "category_accuracy": cat_acc,
        "function_localization": loc_acc,
        "findings": all_findings
    }
    (scratch_dir / "eval_summary.json").write_text(json.dumps(results_summary, indent=2), encoding="utf-8")

if __name__ == "__main__":
    run_evaluation()
