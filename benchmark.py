"""Local, reproducible benchmark runner for VLD datasets and ground truth labels."""
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Set


def canonical(value: str) -> str:
    aliases = {"selfdestruct": "dangerous_selfdestruct", "dangerous_selfdestruct": "dangerous_selfdestruct"}
    key = str(value or "").lower().replace("-", "_").replace(" ", "_")
    return aliases.get(key, key)


def load_ground_truth(path: Path | None) -> Dict[str, Set[str]]:
    """Load ``contract -> vulnerability types`` from a local JSON or CSV file."""
    if path is None:
        return {}
    if path.suffix.lower() == ".json":
        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw, dict) and "contracts" in raw:
            raw = raw["contracts"]
        return {str(name): {canonical(item) for item in (labels if isinstance(labels, list) else [labels])} for name, labels in raw.items()}
    labels: Dict[str, Set[str]] = {}
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            name = row.get("contract") or row.get("path") or row.get("file")
            label = row.get("vulnerability") or row.get("label") or row.get("vulnerability_type")
            if name and label:
                labels.setdefault(name, set()).add(canonical(label))
    return labels


def labels_for(contract: Path, dataset: Path, ground_truth: Dict[str, Set[str]]) -> Set[str]:
    relative = contract.relative_to(dataset).as_posix()
    if relative in ground_truth:
        return ground_truth[relative]
    if contract.name in ground_truth:
        return ground_truth[contract.name]
    # Curated datasets in this repository encode one expected category in the
    # parent directory; unlabeled contracts remain evaluation-neutral.
    return {canonical(contract.parent.name)} if contract.parent.name not in {"contracts", "no_errors"} else set()


def run_contract(contract: Path, model: str, output: Path, with_poc: bool) -> Dict:
    command = [sys.executable, "main.py", "--contract", str(contract), "--no-rag", "--all-models", model, "--export-json", str(output)]
    if not with_poc:
        command.append("--skip-poc")
    started = time.perf_counter()
    process = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
    runtime = time.perf_counter() - started
    if process.returncode != 0 or not output.exists():
        return {"error": process.stderr[-4000:] or process.stdout[-4000:], "runtime_seconds": runtime}
    result = json.loads(output.read_text(encoding="utf-8"))
    result["runtime_seconds"] = runtime
    return result


def score(expected: Set[str], detected: Set[str]) -> Dict[str, int]:
    return {"tp": len(expected & detected), "fp": len(detected - expected), "fn": len(expected - detected), "tn": int(not expected and not detected)}


def aggregate(records: Iterable[Dict]) -> Dict:
    totals = Counter()
    confidence, runtimes, poc = [], [], Counter()
    for record in records:
        totals.update(record["confusion"])
        runtimes.append(record["runtime_seconds"])
        confidence.extend(record["confidences"])
        poc.update(record["poc_metrics"])
    precision = totals["tp"] / (totals["tp"] + totals["fp"]) if totals["tp"] + totals["fp"] else 0.0
    recall = totals["tp"] / (totals["tp"] + totals["fn"]) if totals["tp"] + totals["fn"] else 0.0
    return {"contracts": len(runtimes), **totals, "precision": precision, "recall": recall,
            "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
            "average_confidence": sum(confidence) / len(confidence) if confidence else 0.0,
            "average_runtime_seconds": sum(runtimes) / len(runtimes) if runtimes else 0.0,
            "poc_generation_rate": poc["generated_pocs"] / len(runtimes) if runtimes else 0.0,
            "compilation_rate": poc["compiled_pocs"] / poc["generated_pocs"] if poc["generated_pocs"] else 0.0,
            "execution_rate": poc["executed_pocs"] / poc["compiled_pocs"] if poc["compiled_pocs"] else 0.0,
            "successful_exploit_rate": poc["successful_exploits"] / poc["executed_pocs"] if poc["executed_pocs"] else 0.0}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a local VLD benchmark with JSON/CSV ground truth.")
    parser.add_argument("--dataset", default="benchmark_data/contracts", help="Dataset directory scanned recursively for .sol files")
    parser.add_argument("--ground-truth", help="Optional local JSON or CSV labels")
    parser.add_argument("--models", default="qwen2.5-coder:7b", help="Comma-separated local Ollama models")
    parser.add_argument("--with-poc", action="store_true", help="Enable PoC generation, compilation, and execution metrics")
    parser.add_argument("--output-dir", default="benchmark_results", help="Directory for benchmark artifacts")
    args = parser.parse_args()
    dataset, output_dir = Path(args.dataset), Path(args.output_dir)
    contracts = sorted(dataset.rglob("*.sol"))
    if not contracts:
        raise SystemExit(f"No Solidity contracts found under {dataset}")
    truth = load_ground_truth(Path(args.ground_truth) if args.ground_truth else None)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir.mkdir(parents=True, exist_ok=True)
    comparison = {}
    for model in [item.strip() for item in args.models.split(",") if item.strip()]:
        records = []
        for contract in contracts:
            result_file = output_dir / f"{stamp}_{model.replace(':', '_')}_{contract.stem}.json"
            result = run_contract(contract, model, result_file, args.with_poc)
            findings = result.get("rechecked_vulnerabilities", [])
            detected = {canonical(item.get("vulnerability_type")) for item in findings}
            expected = labels_for(contract, dataset, truth)
            records.append({"contract": contract.relative_to(dataset).as_posix(), "expected": sorted(expected), "detected": sorted(detected),
                            "confusion": score(expected, detected), "confidences": [float(item.get("skeptic_confidence", item.get("confidence_score", 0)) or 0) for item in findings],
                            "poc_metrics": result.get("poc_metrics", {}), "runtime_seconds": result.get("runtime_seconds", 0), "error": result.get("error", "")})
        comparison[model] = {"summary": aggregate(records), "records": records}
    report = {"timestamp": stamp, "dataset": str(dataset), "ground_truth": str(args.ground_truth or "directory labels"), "models": comparison}
    output = output_dir / f"benchmark_report_{stamp}.json"
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({model: data["summary"] for model, data in comparison.items()}, indent=2))
    print(f"Benchmark report: {output}")


if __name__ == "__main__":
    main()
