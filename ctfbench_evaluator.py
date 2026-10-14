#!/usr/bin/env python3
"""
CTFBench Evaluator

This script evaluates smart contract vulnerability detection tools using the CTFBench methodology.
It calculates two key metrics:
1. VDR (Vulnerability Detection Rate) - The proportion of detected injected vulnerabilities
2. OI (Overreporting Index) - False positives per line of code in error-free contracts

Based on the benchmark_evaluator.py script with modifications to adapt to CTFBench metrics.
"""

import os
import re
import json
import glob
import time
import asyncio
import argparse
from typing import Dict, List, Tuple, Optional, Set, Any
from pathlib import Path
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import logging
from datetime import datetime
from collections import defaultdict
from llm_agents.config import ModelConfig
from llm_agents.ollama_client import OllamaClient
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ctfbench_evaluation.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ctfbench_evaluator")

# Constants
UPLOADS_DIR = "reports"
BENCHMARK_DATA_DIR = "benchmark_data"
BENCHMARK_RESULTS_DIR = "benchmark_results"

# Directory structure within uploads
WITH_ERROR_DIR = "with_error"
NO_ERROR_DIR = "no_error"

# LLM Evaluation settings
EVAL_MODEL = "o3-mini"  # Model for evaluation (as specified in the paper)
EVAL_MAX_ATTEMPTS = 3  # Max retry attempts for LLM evaluation
EVAL_TEMPERATURE = 0.1  # Temperature for evaluation prompts
EVAL_RUNS = 1  # Number of independent trials for LLM evaluation

# Categories
CATEGORIES = [
    "access_control",
    "arithmetic_security",
    "boundary_condition",
    "cryptoeconomic_security",
    "data_structure_security",
    "gas_security",
    "privacy_crypto_security"
]

# Define contract sizes (lines of code) for OI calculation
CONTRACT_SIZES = {
    "access_control": 65,
    "arithmetic_security": 122,
    "boundary_condition": 70,
    "cryptoeconomic_security": 34,
    "data_structure_security": 46,
    "gas_security": 51,
    "privacy_crypto_security": 66
}

class CTFBenchEvaluator:
    """Evaluates vulnerability reports against ground truth synopsis files using CTFBench metrics."""

    def __init__(self,
                 uploads_dir: str = UPLOADS_DIR,
                 benchmark_data_dir: str = BENCHMARK_DATA_DIR,
                 results_dir: str = BENCHMARK_RESULTS_DIR,
                 use_llm: bool = True,
                 eval_model: str = EVAL_MODEL,
                 max_workers: int = 5,
                 eval_runs: int = EVAL_RUNS):
        """
        Initialize the benchmark evaluator.

        Args:
            uploads_dir: Directory containing generated reports
            benchmark_data_dir: Directory containing benchmark data with errors
            results_dir: Directory to save evaluation results
            use_llm: Whether to use LLM-based evaluation
            eval_model: LLM model to use for evaluation
            max_workers: Maximum number of parallel workers
            eval_runs: Number of independent trials for LLM evaluation
        """
        self.uploads_dir = Path(uploads_dir)
        self.benchmark_data_dir = Path(benchmark_data_dir)
        self.results_dir = Path(results_dir)
        self.use_llm = use_llm
        self.eval_model = eval_model
        self.max_workers = max_workers
        self.eval_runs = eval_runs

        # Check if required directories exist
        self._check_directories()

        # Create model config for LLM client
        self.model_config = ModelConfig()

        # Initialize OpenAI client if needed
        self.client = None
        if self.use_llm:
            self._setup_llm_client()

        # Create results directory if it doesn't exist
        os.makedirs(self.results_dir, exist_ok=True)

        # Store evaluation results
        self.results = {}

    def _check_directories(self):
        """Check if required directories exist and create them if necessary."""
        # Check uploads directory
        if not os.path.exists(self.uploads_dir):
            logger.warning(f"Uploads directory {self.uploads_dir} does not exist. Creating it...")
            os.makedirs(self.uploads_dir, exist_ok=True)

        # Check with_error and no_error directories
        with_error_dir = self.uploads_dir / WITH_ERROR_DIR
        no_error_dir = self.uploads_dir / NO_ERROR_DIR

        if not os.path.exists(with_error_dir):
            logger.warning(f"With-error directory {with_error_dir} does not exist. Creating it...")
            os.makedirs(with_error_dir, exist_ok=True)

        if not os.path.exists(no_error_dir):
            logger.warning(f"No-error directory {no_error_dir} does not exist. Creating it...")
            os.makedirs(no_error_dir, exist_ok=True)

        # Check benchmark data directories
        if not os.path.exists(self.benchmark_data_dir):
            logger.error(f"Benchmark data directory {self.benchmark_data_dir} does not exist")
            logger.error("Please ensure the benchmark data is properly set up")

        # Check for synopsis directory
        synopsis_dir = self.benchmark_data_dir / "synopsis"
        if not os.path.exists(synopsis_dir):
            logger.error(f"Synopsis directory {synopsis_dir} does not exist")
            logger.error("Please ensure the benchmark data is properly set up")

        # Create results directory
        os.makedirs(self.results_dir, exist_ok=True)

    def _setup_llm_client(self):
        """Set up the local Ollama LLM client for evaluation."""
        try:
            self.client = OllamaClient(
                base_url=self.model_config.base_url,
                model=self.eval_model,
                timeout=self.model_config.ollama_request_timeout
            )
            logger.info(f"LLM client set up with model {self.eval_model}")
        except Exception as e:
            logger.error(f"Failed to initialize local Ollama client: {e}")
            logger.warning("Falling back to string matching evaluation")
            self.use_llm = False

    async def evaluate_all(self, report_dirs: List[str] = None) -> Dict:
        """
        Evaluate all reports across specified directories.

        Args:
            report_dirs: List of report directories to evaluate (if None, find all directories)

        Returns:
            Dict containing evaluation results
        """
        # Check if uploads directory exists
        with_error_dir = self.uploads_dir / WITH_ERROR_DIR
        no_error_dir = self.uploads_dir / NO_ERROR_DIR

        if not os.path.exists(with_error_dir) or not os.path.exists(no_error_dir):
            logger.error(f"Required directories {with_error_dir} or {no_error_dir} do not exist")
            return {}

        # If no report dirs provided, find all subdirectories in with_error
        if not report_dirs:
            report_dirs = [d.name for d in with_error_dir.iterdir()
                          if d.is_dir() and not d.name.startswith('.')]

        if not report_dirs:
            logger.warning(f"No report directories found in {with_error_dir}")
            return {}

        logger.info(f"Found {len(report_dirs)} report directories: {report_dirs}")

        # Process each directory
        all_results = {}
        for report_dir in report_dirs:
            logger.info(f"Evaluating reports in {report_dir}")

            # Evaluate reports with errors (for VDR)
            with_error_results = await self.evaluate_directory(report_dir, is_with_error=True)

            # Evaluate reports without errors (for OI)
            no_error_results = await self.evaluate_directory(report_dir, is_with_error=False)

            # Combine results
            combined_results = {
                "with_error": with_error_results,
                "no_error": no_error_results
            }

            all_results[report_dir] = combined_results

        self.results = all_results
        return all_results

    async def evaluate_directory(self, report_dir: str, is_with_error: bool = True) -> Dict:
        """
        Evaluate all reports in a specific directory.

        Args:
            report_dir: Name of the report directory
            is_with_error: Whether this directory contains reports with errors (True) or without errors (False)

        Returns:
            Dict containing evaluation results for the directory
        """
        # Determine the base directory based on whether we're evaluating with_error or no_error
        base_dir = self.uploads_dir / (WITH_ERROR_DIR if is_with_error else NO_ERROR_DIR)
        dir_path = base_dir / report_dir

        if not dir_path.exists() or not dir_path.is_dir():
            logger.error(f"Directory {dir_path} does not exist")
            return {}

        # Get list of all report files (.md files) in the directory
        report_files = list(dir_path.glob("*.md"))
        logger.info(f"Found {len(report_files)} report files in {dir_path}")

        # Process all reports
        results = {}
        error_reports = []

        for report_file in report_files:
            category = self._get_category_from_filename(report_file.name)
            if category:
                error_reports.append((report_file, category))
            else:
                logger.warning(f"Could not determine category for {report_file.name}")

        if error_reports:
            logger.info(f"Processing {len(error_reports)} reports from {dir_path}")
            error_tasks = []

            for report_file, category in error_reports:
                # For with_error files, compare against synopsis
                # For no_error files, calculate false positives only
                task = self.evaluate_report(report_file, category, is_with_error)
                error_tasks.append(task)

            error_results = await asyncio.gather(*error_tasks)
            for result in error_results:
                if result:  # Skip None results
                    results[result["category"]] = result

        return results

    async def evaluate_report(self, report_file: Path, category: str, is_with_error: bool) -> Dict:
        """
        Evaluate a single report file.

        Args:
            report_file: Path to the report file
            category: Vulnerability category
            is_with_error: Whether this report is for a contract with errors (True) or without errors (False)

        Returns:
            Dict containing evaluation results
        """
        logger.info(f"Evaluating {'with-error' if is_with_error else 'no-error'} report {report_file.name} for category {category}")

        # Read report content
        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                report_content = f.read().strip()

            # Check if report is empty or too short to be meaningful
            if not report_content or len(report_content) < 50:
                logger.warning(f"Report file {report_file} is empty or too short to analyze")
                if is_with_error:
                    # For with_error reports, count as a false negative
                    return {
                        "category": category,
                        "file": report_file.name,
                        "true_positive": 0,
                        "false_positive": 0,
                        "false_negative": 1,
                        "lines_of_code": CONTRACT_SIZES.get(category, 0),
                        "vdr": 0.0,
                        "oi": 0.0,
                        "analysis": "Report file is empty or too short to analyze",
                        "evaluation_method": "error",
                        "llm_results": []
                    }
                else:
                    # For no_error reports, count as 0 false positives
                    return {
                        "category": category,
                        "file": report_file.name,
                        "true_positive": 0,  # N/A for no-error reports
                        "false_positive": 0,
                        "false_negative": 0,  # N/A for no-error reports
                        "lines_of_code": CONTRACT_SIZES.get(category, 0),
                        "vdr": 0.0,  # N/A for no-error reports
                        "oi": 0.0,
                        "analysis": "Report file is empty or too short to analyze",
                        "evaluation_method": "error",
                        "llm_results": []
                    }
        except Exception as e:
            logger.error(f"Error reading report file {report_file}: {e}")
            return None

        if is_with_error:
            # For with_error reports, compare against synopsis
            # Read synopsis content (ground truth)
            synopsis_path = self.benchmark_data_dir / "synopsis" / f"{category}.txt"
            if not os.path.exists(synopsis_path):
                # Try alternate extensions if .txt doesn't exist
                alt_paths = [
                    self.benchmark_data_dir / "synopsis" / f"{category}.md",
                    self.benchmark_data_dir / "synopsis" / f"{category}"
                ]

                for alt_path in alt_paths:
                    if os.path.exists(alt_path):
                        synopsis_path = alt_path
                        break
                else:
                    logger.error(f"Synopsis file for {category} does not exist")
                    logger.warning(f"Looked for: {synopsis_path} and alternatives")
                    # Return a default evaluation with a warning message instead of failing
                    return {
                        "category": category,
                        "file": report_file.name,
                        "true_positive": 0,
                        "false_positive": 0,
                        "false_negative": 1,  # Assuming we missed a vulnerability since we couldn't compare
                        "lines_of_code": CONTRACT_SIZES.get(category, 0),
                        "vdr": 0.0,
                        "oi": 0.0,
                        "analysis": f"Unable to evaluate: synopsis file for {category} not found",
                        "evaluation_method": "error",
                        "llm_results": []
                    }

            try:
                with open(synopsis_path, 'r', encoding='utf-8') as f:
                    synopsis_content = f.read().strip()
            except Exception as e:
                logger.error(f"Error reading synopsis file {synopsis_path}: {e}")
                # Return a default evaluation with a warning message instead of failing
                return {
                    "category": category,
                    "file": report_file.name,
                    "true_positive": 0,
                    "false_positive": 0,
                    "false_negative": 1,  # Assuming we missed a vulnerability since we couldn't compare
                    "lines_of_code": CONTRACT_SIZES.get(category, 0),
                    "vdr": 0.0,
                    "oi": 0.0,
                    "analysis": f"Unable to evaluate: error reading synopsis file - {str(e)}",
                    "evaluation_method": "error",
                    "llm_results": []
                }

            # Evaluate using LLM or string matching
            if self.use_llm and self.client:
                # Run multiple LLM evaluations
                llm_results = []
                total_tp = 0
                total_fp = 0

                for run in range(self.eval_runs):
                    logger.info(f"LLM evaluation run {run+1}/{self.eval_runs} for {category}")
                    evaluation = await self._evaluate_with_llm(report_content, synopsis_content, category, run)
                    llm_results.append(evaluation)

                    # Sum up true positives and false positives across runs
                    total_tp += evaluation["true_positive"]
                    total_fp += evaluation["false_positive"]

                # Calculate average metrics across all runs
                avg_tp = total_tp / self.eval_runs
                avg_fp = total_fp / self.eval_runs

                # In CTFBench, there's exactly one vulnerability per contract
                # So false_negative = 1 - true_positive for each contract
                avg_fn = self.eval_runs - total_tp

                # Final evaluation is average across all runs
                evaluation = {
                    "true_positive": avg_tp,
                    "false_positive": avg_fp,
                    "false_negative": avg_fn / self.eval_runs,
                    "analysis": f"Averaged results over {self.eval_runs} LLM evaluation runs",
                    "evaluation_method": "llm",
                    "llm_results": llm_results  # Store individual run results for reference
                }
            else:
                evaluation = self._evaluate_with_string_matching(report_content, synopsis_content)
                evaluation["llm_results"] = []  # Add empty list for consistency

            # Get the contract's lines of code for this category
            lines_of_code = CONTRACT_SIZES.get(category, 0)

            # Calculate CTFBench metrics
            # VDR = TP/V where V is the total number of vulnerabilities (1 per contract in CTFBench)
            vdr = evaluation["true_positive"]  # Since each contract has 1 vulnerability, this is between 0 and 1

            # OI = FP/LoC where FP is the number of false positives and LoC is lines of code
            oi = evaluation["false_positive"] / lines_of_code if lines_of_code > 0 else 0

            # Combine results
            result = {
                "category": category,
                "file": report_file.name,
                "true_positive": evaluation["true_positive"],
                "false_positive": evaluation["false_positive"],
                "false_negative": evaluation["false_negative"],
                "lines_of_code": lines_of_code,
                "vdr": vdr,
                "oi": oi,
                "analysis": evaluation["analysis"],
                "evaluation_method": evaluation["evaluation_method"],
                "llm_results": evaluation["llm_results"]
            }
        else:
            # For no_error reports, calculate false positives only
            # Count how many vulnerabilities were reported in a no-error contract
            if self.use_llm and self.client:
                # Use LLM to count false positives
                fp_count = await self._count_false_positives_with_llm(report_content, category)
            else:
                # Use string matching to count false positives
                fp_count = self._count_false_positives_with_string_matching(report_content)

            # Get the contract's lines of code for this category
            lines_of_code = CONTRACT_SIZES.get(category, 0)

            # Calculate OI = FP/LoC
            oi = fp_count / lines_of_code if lines_of_code > 0 else 0

            # Combine results
            result = {
                "category": category,
                "file": report_file.name,
                "true_positive": 0,  # N/A for no-error reports
                "false_positive": fp_count,
                "false_negative": 0,  # N/A for no-error reports
                "lines_of_code": lines_of_code,
                "vdr": 0.0,  # N/A for no-error reports
                "oi": oi,
                "analysis": f"Found {fp_count} false positives in no-error contract",
                "evaluation_method": "llm" if self.use_llm and self.client else "string_matching",
                "llm_results": []
            }

        return result

    async def _evaluate_with_llm(self, report_content: str, synopsis_content: str, category: str, run_index: int = 0) -> Dict:
        """
        Evaluate a report against a synopsis using an LLM.

        Args:
            report_content: Content of the report
            synopsis_content: Content of the synopsis (ground truth)
            category: Vulnerability category
            run_index: Index of the current run (for multiple trials)

        Returns:
            Dict containing evaluation results
        """
        # As defined in the paper, we use DeepSeek R1 to determine:
        # 1. Whether the injected vulnerability was detected (YES/NO)
        # 2. How many false positives were reported

        # First, check if the vulnerability was detected
        detection_prompt = f"""You are an expert smart contract security evaluator. Your task is to determine if the following security report correctly identifies the vulnerability described in the synopsis.

VULNERABILITY SYNOPSIS:
```
{synopsis_content}
```

SECURITY REPORT:
```
{report_content}
```

The synopsis describes what's wrong with the contract. Based only on the above information, answer with YES or NO:
Does the security report correctly identify the vulnerability described in the synopsis? Ignore the confidence scores, getting the nature of the vulnerability is enough.

Your answer (YES/NO):"""

        # Count false positives
        fp_prompt = f"""You are an expert smart contract security evaluator. Your task is to count how many FALSE POSITIVE vulnerabilities are reported.

VULNERABILITY SYNOPSIS (the actual vulnerability):
```
{synopsis_content}
```

SECURITY REPORT:
```
{report_content}
```

The synopsis describes what's wrong with the contract. Vulnerabilities reported that are of a different nature should be counted as false positives.
ONLY COUNT THEM IF THE CONFIDENCE IS MORE THAN 0.5
Count the number of false positives (vulnerabilities reported that are different from the one in the synopsis) and provide just a number:"""

        # Try to get responses with retries
        detected = False
        false_positives = 0

        # Detection evaluation
        for attempt in range(EVAL_MAX_ATTEMPTS):
            try:
                detection_response = await asyncio.to_thread(
                    self.client.chat.completions.create,
                    model=self.eval_model,
                    messages=[{"role": "user", "content": detection_prompt}],
                )

                # Parse the response
                detection_text = detection_response.choices[0].message.content.strip().upper()
                if "YES" in detection_text:
                    detected = True
                    logger.info(f"Run {run_index+1}: Vulnerability detected in {category}")
                else:
                    logger.info(f"Run {run_index+1}: Vulnerability NOT detected in {category}")

                break  # Success, exit retry loop
            except Exception as e:
                logger.warning(f"LLM detection evaluation attempt {attempt+1} failed: {e}")
                if attempt < EVAL_MAX_ATTEMPTS - 1:
                    # Wait before retrying
                    await asyncio.sleep(1 * (attempt + 1))
                else:
                    logger.error(f"LLM detection evaluation failed after {EVAL_MAX_ATTEMPTS} attempts")
                    # Fall back to string matching for this run
                    return self._evaluate_with_string_matching(report_content, synopsis_content)

        # False positive evaluation
        for attempt in range(EVAL_MAX_ATTEMPTS):
            try:
                fp_response = await asyncio.to_thread(
                    self.client.chat.completions.create,
                    model=self.eval_model,
                    messages=[{"role": "user", "content": fp_prompt}],
                )

                # Parse the response - extract a number
                fp_text = fp_response.choices[0].message.content.strip()
                # Try to extract a number from the response
                numbers = re.findall(r'\b\d+\b', fp_text)
                if numbers:
                    false_positives = int(numbers[0])
                    logger.info(f"Run {run_index+1}: {false_positives} false positives found in {category}")
                else:
                    # If no number found, use a default value
                    false_positives = 0 if "zero" in fp_text.lower() or "no" in fp_text.lower() else 1
                    logger.info(f"Run {run_index+1}: Using default {false_positives} false positives for {category} (no clear number found)")

                break  # Success, exit retry loop
            except Exception as e:
                logger.warning(f"LLM false positive evaluation attempt {attempt+1} failed: {e}")
                if attempt < EVAL_MAX_ATTEMPTS - 1:
                    # Wait before retrying
                    await asyncio.sleep(1 * (attempt + 1))
                else:
                    logger.error(f"LLM false positive evaluation failed after {EVAL_MAX_ATTEMPTS} attempts")
                    # Use string matching method's false positive count
                    str_eval = self._evaluate_with_string_matching(report_content, synopsis_content)
                    false_positives = str_eval["false_positive"]

        # Return evaluation result
        result = {
            "true_positive": 1 if detected else 0,  # In CTFBench, each contract has exactly 1 vulnerability
            "false_positive": false_positives,
            "false_negative": 0 if detected else 1,
            "analysis": f"Run {run_index+1}: LLM {'detected' if detected else 'did not detect'} the vulnerability and found {false_positives} false positives",
            "evaluation_method": "llm"
        }

        return result

    async def _count_false_positives_with_llm(self, report_content: str, category: str) -> int:
        """
        Count false positives in a no-error contract report using LLM.

        Args:
            report_content: Content of the report
            category: Vulnerability category

        Returns:
            Number of false positives
        """
        # Prompt to count vulnerabilities reported in a no-error contract
        fp_prompt = f"""You are an expert smart contract security evaluator. Your task is to count how many vulnerabilities are reported in the following security report.

SECURITY REPORT:
```
{report_content}
```

This contract should NOT have any vulnerabilities. Any reported vulnerabilities are false positives.
Count the number of vulnerabilities reported (keep in mind the same vulnerability might be mentioned multiple times - only count it once).
ONLY COUNT VULNERABILITIES WITH CONFIDENCE GREATER THAN 0.5.
Provide just a number:"""

        # Try to get response with retries
        false_positives = 0

        for attempt in range(EVAL_MAX_ATTEMPTS):
            try:
                fp_response = await asyncio.to_thread(
                    self.client.chat.completions.create,
                    model=self.eval_model,
                    messages=[{"role": "user", "content": fp_prompt}],
                )

                # Parse the response - extract a number
                fp_text = fp_response.choices[0].message.content.strip()
                # Try to extract a number from the response
                numbers = re.findall(r'\b\d+\b', fp_text)
                if numbers:
                    false_positives = int(numbers[0])
                    logger.info(f"{false_positives} false positives found in no-error contract for {category}")
                else:
                    # If no number found, use a default value
                    false_positives = 0 if "zero" in fp_text.lower() or "no" in fp_text.lower() else 1
                    logger.info(f"Using default {false_positives} false positives for no-error contract {category} (no clear number found)")

                break  # Success, exit retry loop
            except Exception as e:
                logger.warning(f"LLM false positive count attempt {attempt+1} failed: {e}")
                if attempt < EVAL_MAX_ATTEMPTS - 1:
                    # Wait before retrying
                    await asyncio.sleep(1 * (attempt + 1))
                else:
                    logger.error(f"LLM false positive count failed after {EVAL_MAX_ATTEMPTS} attempts")
                    # Fall back to string matching
                    return self._count_false_positives_with_string_matching(report_content)

        return false_positives

    def _evaluate_with_string_matching(self, report_content: str, synopsis_content: str) -> Dict:
        """
        Evaluate a report against a synopsis using simple string matching.

        Args:
            report_content: Content of the report
            synopsis_content: Content of the synopsis (ground truth)

        Returns:
            Dict containing evaluation results
        """
        # Extract key terms from the synopsis
        synopsis_terms = self._extract_key_terms(synopsis_content)

        # Check how many terms from the synopsis appear in the report
        matched_terms = [term for term in synopsis_terms if term.lower() in report_content.lower()]

        # Calculate metrics
        true_positive = 1 if matched_terms else 0  # In CTFBench, each contract has exactly 1 vulnerability
        false_negative = 1 - true_positive          # 0 if found, 1 if missed

        # Count false positives (other security issues reported)
        # This is a rough approximation - count security terms in report not in synopsis
        report_terms = self._extract_key_terms(report_content)
        false_positive = len([term for term in report_terms
                             if term.lower() not in synopsis_content.lower()
                             and self._is_security_term(term)])

        result = {
            "true_positive": true_positive,
            "false_positive": false_positive,
            "false_negative": false_negative,
            "analysis": f"Matched {len(matched_terms)} terms from synopsis of {len(synopsis_terms)} key terms",
            "evaluation_method": "string_matching",
            "llm_results": []  # Add empty list for consistency
        }

        return result

    def _count_false_positives_with_string_matching(self, report_content: str) -> int:
        """
        Count false positives in a no-error contract report using string matching.

        Args:
            report_content: Content of the report

        Returns:
            Number of false positives
        """
        # Count occurrences of security-related terms and vulnerability mentions
        security_terms = [
            "vulnerability", "attack", "exploit", "security issue", "risk", "bug", "flaw",
            "weakness", "threat", "compromise", "breach", "critical", "severe"
        ]

        # Count mentions of specific vulnerability types
        vuln_types = [
            "reentrancy", "overflow", "underflow", "access control", "authorization",
            "front-running", "oracle manipulation", "price manipulation", "flash loan attack",
            "time manipulation", "randomness", "denial of service", "dos", "unchecked",
            "gas", "precision", "arithmetic", "rounding", "race condition"
        ]

        # Count lines mentioning vulnerabilities
        fp_count = 0
        lines = report_content.lower().split('\n')
        counted_vulns = set()  # Track already counted vulnerability types

        for line in lines:
            # Check for vulnerability mentions
            for vuln in vuln_types:
                if vuln in line and vuln not in counted_vulns:
                    # Only count each vulnerability type once
                    counted_vulns.add(vuln)
                    fp_count += 1
                    break

        return fp_count

    def _extract_key_terms(self, text: str) -> List[str]:
        """
        Extract key security-related terms from text.

        Args:
            text: Text to extract terms from

        Returns:
            List of key terms
        """
        # Common security-related terms
        security_terms = [
            "reentrancy", "overflow", "underflow", "access control", "authorization",
            "front-running", "oracle", "price manipulation", "flash loan", "time manipulation",
            "randomness", "denial of service", "dos", "unchecked", "gas", "precision",
            "arithmetic", "rounding", "race condition", "centralization", "governance",
            "privilege", "permission", "authentication", "validation", "boundary", "check"
        ]

        # Find all occurrences of security terms
        found_terms = []
        for term in security_terms:
            if term.lower() in text.lower():
                found_terms.append(term)

        # Also extract function names
        function_pattern = r"\b(function|modifier)\s+(\w+)"
        for match in re.finditer(function_pattern, text):
            found_terms.append(match.group(2))

        return found_terms

    def _is_security_term(self, term: str) -> bool:
        """
        Check if a term is security-related.

        Args:
            term: Term to check

        Returns:
            True if the term is security-related, False otherwise
        """
        security_keywords = [
            "vulnerability", "attack", "exploit", "security", "risk", "issue",
            "problem", "bug", "flaw", "weakness", "threat", "compromise", "breach",
            "critical", "severe", "overflow", "underflow", "reentrancy", "access",
            "control", "authorization", "authentication", "validation", "check"
        ]

        return any(keyword in term.lower() for keyword in security_keywords)

    def _get_category_from_filename(self, filename: str) -> Optional[str]:
        """
        Extract the vulnerability category from a filename.

        Args:
            filename: Name of the file

        Returns:
            Category name or None if cannot be determined
        """
        # First, remove file extension
        base_name = os.path.splitext(filename)[0]

        # Check for direct category match
        for category in CATEGORIES:
            if category == base_name:
                return category

        # Check for category in the filename
        for category in CATEGORIES:
            if category in filename.lower():
                return category

        # If no direct match, try to parse from filename patterns
        # Example patterns:
        # - "category.md"
        # - "analysis_report_Contract.sol_timestamp.md"

        # Try to match known contract names to categories
        contract_to_category = {
            "Voting": "access_control",
            "Lending": "arithmetic_security",
            "SuperToken": "boundary_condition",
            "OracleFlashLoan": "cryptoeconomic_security",
            "Vesting": "data_structure_security",
            "MerkleDrop": "gas_security",
            "EncryptedStorage": "privacy_crypto_security"
        }

        for contract, category in contract_to_category.items():
            if contract in filename:
                return category

        # Parse parts of the filename to find a match
        parts = filename.split('_')
        for category in CATEGORIES:
            if category in parts:
                return category

        return None

    def generate_summary(self) -> Dict:
        """
        Generate a summary of the evaluation results using CTFBench metrics.

        Returns:
            Dict containing summary statistics
        """
        if not self.results:
            logger.warning("No results to summarize")
            return {}

        summary = {}

        # Calculate average metrics for each report directory
        for report_dir, results in self.results.items():
            with_error_results = results.get("with_error", {})
            no_error_results = results.get("no_error", {})

            # Process with_error results for VDR
            total_tp = 0
            total_fn = 0

            for category, result in with_error_results.items():
                total_tp += result.get("true_positive", 0)
                total_fn += result.get("false_negative", 0)

            # Process no_error results for OI
            total_fp = 0
            total_loc = 0

            for category, result in no_error_results.items():
                total_fp += result.get("false_positive", 0)
                total_loc += result.get("lines_of_code", 0)

            # Calculate CTFBench metrics
            # VDR (Vulnerability Detection Rate)
            total_vulns = total_tp + total_fn
            vdr = total_tp / total_vulns if total_vulns > 0 else 0

            # OI (Overreporting Index)
            oi = total_fp / total_loc if total_loc > 0 else 0

            # Add evaluation methods used
            evaluation_methods = defaultdict(int)
            for results_dict in [with_error_results, no_error_results]:
                for result in results_dict.values():
                    method = result.get("evaluation_method", "unknown")
                    evaluation_methods[method] += 1

            # Store summary
            summary[report_dir] = {
                "vdr": vdr,
                "oi": oi,
                "true_positive": total_tp,
                "false_positive": total_fp,
                "false_negative": total_fn,
                "total_loc": total_loc,
                "evaluation_methods": dict(evaluation_methods)
            }

        return summary

    def save_results(self, filename: str = None) -> str:
        """
        Save evaluation results to a JSON file.

        Args:
            filename: Name of the file to save results to (without extension)

        Returns:
            Path to the saved file
        """
        if not self.results:
            logger.warning("No results to save")
            return ""

        # Generate filename based on timestamp if not provided
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ctfbench_results_{timestamp}"

        # Ensure .json extension
        if not filename.endswith(".json"):
            filename += ".json"

        # Create path in results directory
        file_path = self.results_dir / filename

        # Save results to JSON file
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2)
            logger.info(f"Results saved to {file_path}")
            return str(file_path)
        except Exception as e:
            logger.error(f"Error saving results to {file_path}: {e}")
            return ""

    def generate_visualizations(self) -> List[str]:
        """
        Generate visualizations of the evaluation results using CTFBench metrics.

        Returns:
            List of paths to generated visualization files
        """
        if not self.results:
            logger.warning("No results to visualize")
            return []

        # Get summary statistics
        summary = self.generate_summary()

        # Prepare data for visualization
        viz_files = []

        # 1. VDR-OI plot (primary CTFBench visualization)
        vdr_oi_file = self._plot_vdr_oi_space(summary)
        if vdr_oi_file:
            viz_files.append(vdr_oi_file)

        # 2. VDR by category
        vdr_by_category_file = self._plot_vdr_by_category()
        if vdr_by_category_file:
            viz_files.append(vdr_by_category_file)

        # 3. OI by category
        oi_by_category_file = self._plot_oi_by_category()
        if oi_by_category_file:
            viz_files.append(oi_by_category_file)

        return viz_files

    def _plot_vdr_oi_space(self, summary: Dict) -> str:
        """
        Plot auditors in the VDR-OI space.

        Args:
            summary: Summary statistics

        Returns:
            Path to the generated plot file
        """
        # Prepare data
        models = []
        vdr_vals = []
        oi_vals = []

        for model, stats in summary.items():
            models.append(model)
            vdr_vals.append(stats["vdr"])
            oi_vals.append(stats["oi"])

        # Create VDR-OI plot
        plt.figure(figsize=(10, 8))

        # Plot quadrant lines
        plt.axhline(y=0.5, color='gray', linestyle='--', alpha=0.5)
        plt.axvline(x=0.05, color='gray', linestyle='--', alpha=0.5)

        # Add quadrant labels
        plt.text(0.025, 0.75, "Optimal Auditor", fontsize=11, ha='center')
        plt.text(0.15, 0.75, "Diligent but Noisy\nAuditor", fontsize=11, ha='center')
        plt.text(0.025, 0.25, "Conservative\nAuditor", fontsize=11, ha='center')
        plt.text(0.15, 0.25, "Unreliable\nAuditor", fontsize=11, ha='center')

        # Scatter plot for models
        scatter = plt.scatter(oi_vals, vdr_vals, s=100, alpha=0.7)

        # Add labels for each point
        for i, model in enumerate(models):
            plt.annotate(model, (oi_vals[i], vdr_vals[i]),
                         xytext=(5, 5), textcoords='offset points')

        # Set plot details
        plt.xlabel('Overreporting Index (OI)')
        plt.ylabel('Vulnerability Detection Rate (VDR)')
        plt.title('CTFBench: Model Performance in VDR-OI Space')
        plt.xlim(-0.01, max(oi_vals) * 1.3 + 0.01 if oi_vals else 0.2)  # Leave some space
        plt.ylim(-0.05, 1.05)  # VDR is between 0 and 1
        plt.grid(True, alpha=0.3)

        # Save plot
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = self.results_dir / f"vdr_oi_space_{timestamp}.png"
        plt.savefig(file_path, dpi=300)
        plt.close()

        return str(file_path)

    def _plot_vdr_by_category(self) -> str:
        """
        Plot VDR scores by vulnerability category.

        Returns:
            Path to the generated plot file
        """
        # Prepare data
        categories = []
        model_vdr_scores = defaultdict(list)

        # Process with_error results for VDR by category
        for model, results in self.results.items():
            with_error_results = results.get("with_error", {})

            for category, result in with_error_results.items():
                if category not in categories:
                    categories.append(category)

                # VDR is true_positive for each category (1 vulnerability per contract)
                model_vdr_scores[model].append({
                    "category": category,
                    "vdr": result.get("true_positive", 0)
                })

        if not categories:
            logger.warning("No category data for VDR visualization")
            return ""

        # Create DataFrame for seaborn
        plot_data = []
        for model, scores in model_vdr_scores.items():
            for score_item in scores:
                plot_data.append({
                    "Model": model,
                    "Category": score_item["category"],
                    "VDR": score_item["vdr"]
                })

        df = pd.DataFrame(plot_data)

        # Create plot
        plt.figure(figsize=(14, 7))
        chart = sns.barplot(x="Category", y="VDR", hue="Model", data=df)
        plt.title("Vulnerability Detection Rate (VDR) by Category")
        plt.xticks(rotation=45, ha='right')
        plt.ylim(0, 1.1)
        plt.legend(title="Model", bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.tight_layout()

        # Save plot
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = self.results_dir / f"vdr_by_category_{timestamp}.png"
        plt.savefig(file_path, dpi=300)
        plt.close()

        return str(file_path)

    def _plot_oi_by_category(self) -> str:
        """
        Plot OI scores by vulnerability category.

        Returns:
            Path to the generated plot file
        """
        # Prepare data
        categories = []
        model_oi_scores = defaultdict(list)

        # Process no_error results for OI by category
        for model, results in self.results.items():
            no_error_results = results.get("no_error", {})

            for category, result in no_error_results.items():
                if category not in categories:
                    categories.append(category)

                # Calculate OI for each category
                fp = result.get("false_positive", 0)
                loc = result.get("lines_of_code", 0)
                oi = fp / loc if loc > 0 else 0

                model_oi_scores[model].append({
                    "category": category,
                    "oi": oi
                })

        if not categories:
            logger.warning("No category data for OI visualization")
            return ""

        # Create DataFrame for seaborn
        plot_data = []
        for model, scores in model_oi_scores.items():
            for score_item in scores:
                plot_data.append({
                    "Model": model,
                    "Category": score_item["category"],
                    "OI": score_item["oi"]
                })

        df = pd.DataFrame(plot_data)

        # Create plot
        plt.figure(figsize=(14, 7))
        chart = sns.barplot(x="Category", y="OI", hue="Model", data=df)
        plt.title("Overreporting Index (OI) by Category")
        plt.xticks(rotation=45, ha='right')
        oi_max = df["OI"].max()
        plt.ylim(0, oi_max * 1.1 + 0.01 if oi_max else 0.1)
        plt.legend(title="Model", bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.tight_layout()

        # Save plot
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = self.results_dir / f"oi_by_category_{timestamp}.png"
        plt.savefig(file_path, dpi=300)
        plt.close()

        return str(file_path)

async def main():
    """Main function to run the CTFBench evaluator."""
    parser = argparse.ArgumentParser(description="CTFBench Evaluator for Smart Contract Vulnerability Detection")

    parser.add_argument("--uploads-dir", type=str, default=UPLOADS_DIR,
                       help="Directory containing generated reports")
    parser.add_argument("--benchmark-data-dir", type=str, default=BENCHMARK_DATA_DIR,
                       help="Directory containing benchmark data")
    parser.add_argument("--results-dir", type=str, default=BENCHMARK_RESULTS_DIR,
                       help="Directory to save evaluation results")
    parser.add_argument("--report-dirs", type=str, nargs="+",
                       help="Specific report directories to evaluate")
    parser.add_argument("--use-llm", action="store_true", default=True,
                       help="Use LLM-based evaluation (default: True)")
    parser.add_argument("--no-llm", action="store_false", dest="use_llm",
                       help="Disable LLM-based evaluation")
    parser.add_argument("--eval-model", type=str, default=EVAL_MODEL,
                       help=f"LLM model to use for evaluation (default: {EVAL_MODEL})")
    parser.add_argument("--eval-runs", type=int, default=EVAL_RUNS,
                       help=f"Number of independent trials for LLM evaluation (default: {EVAL_RUNS})")
    parser.add_argument("--load-results", type=str,
                       help="Path to an existing results JSON file to visualize without re-running evaluation")

    args = parser.parse_args()

    # Initialize the evaluator
    evaluator = CTFBenchEvaluator(
        uploads_dir=args.uploads_dir,
        benchmark_data_dir=args.benchmark_data_dir,
        results_dir=args.results_dir,
        use_llm=args.use_llm,
        eval_model=args.eval_model,
        eval_runs=args.eval_runs
    )

    # Check if we should load existing results
    if args.load_results:
        if not os.path.exists(args.load_results):
            logger.error(f"Results file not found: {args.load_results}")
            return

        try:
            logger.info(f"Loading existing results from {args.load_results}")
            with open(args.load_results, 'r', encoding='utf-8') as f:
                evaluator.results = json.load(f)

            # Generate visualizations only
            viz_files = evaluator.generate_visualizations()
            if viz_files:
                logger.info(f"Generated {len(viz_files)} visualization files")
                for f in viz_files:
                    logger.info(f"  - {f}")

            # Print summary
            summary = evaluator.generate_summary()
            logger.info("=== CTFBENCH EVALUATION SUMMARY ===")
            for model, stats in summary.items():
                logger.info(f"\nModel: {model}")
                logger.info(f"Vulnerability Detection Rate (VDR): {stats['vdr']:.4f} ({stats['vdr']*100:.1f}%)")
                logger.info(f"Overreporting Index (OI): {stats['oi']:.4f} ({stats['oi']*100:.1f} FP per 100 lines)")
                logger.info(f"True Positives: {stats['true_positive']}")
                logger.info(f"False Positives: {stats['false_positive']}")
                logger.info(f"False Negatives: {stats['false_negative']}")
                logger.info(f"Total Lines of Code: {stats['total_loc']}")
                logger.info(f"Evaluation Methods: {stats['evaluation_methods']}")

                # Classify the auditor based on VDR and OI
                if stats['vdr'] >= 0.5 and stats['oi'] <= 0.05:
                    auditor_type = "Optimal Auditor"
                elif stats['vdr'] >= 0.5 and stats['oi'] > 0.05:
                    auditor_type = "Diligent but Noisy Auditor"
                elif stats['vdr'] < 0.5 and stats['oi'] <= 0.05:
                    auditor_type = "Conservative Auditor"
                else:
                    auditor_type = "Unreliable Auditor"

                logger.info(f"Auditor Classification: {auditor_type}")

            return
        except Exception as e:
            logger.error(f"Error loading results from {args.load_results}: {e}")
            return

    # Run evaluation
    start_time = time.time()
    results = await evaluator.evaluate_all(args.report_dirs)
    end_time = time.time()

    logger.info(f"Evaluation completed in {end_time - start_time:.2f} seconds")

    # Save results
    results_file = evaluator.save_results()
    if results_file:
        logger.info(f"Results saved to {results_file}")

    # Generate visualizations
    viz_files = evaluator.generate_visualizations()
    if viz_files:
        logger.info(f"Generated {len(viz_files)} visualization files")
        for f in viz_files:
            logger.info(f"  - {f}")

    # Print summary
    summary = evaluator.generate_summary()
    logger.info("=== CTFBENCH EVALUATION SUMMARY ===")
    for model, stats in summary.items():
        logger.info(f"\nModel: {model}")
        logger.info(f"Vulnerability Detection Rate (VDR): {stats['vdr']:.4f} ({stats['vdr']*100:.1f}%)")
        logger.info(f"Overreporting Index (OI): {stats['oi']:.4f} ({stats['oi']*100:.1f} FP per 100 lines)")
        logger.info(f"True Positives: {stats['true_positive']}")
        logger.info(f"False Positives: {stats['false_positive']}")
        logger.info(f"False Negatives: {stats['false_negative']}")
        logger.info(f"Total Lines of Code: {stats['total_loc']}")
        logger.info(f"Evaluation Methods: {stats['evaluation_methods']}")

        # Classify the auditor based on VDR and OI
        if stats['vdr'] >= 0.5 and stats['oi'] <= 0.05:
            auditor_type = "Optimal Auditor"
        elif stats['vdr'] >= 0.5 and stats['oi'] > 0.05:
            auditor_type = "Diligent but Noisy Auditor"
        elif stats['vdr'] < 0.5 and stats['oi'] <= 0.05:
            auditor_type = "Conservative Auditor"
        else:
            auditor_type = "Unreliable Auditor"

        logger.info(f"Auditor Classification: {auditor_type}")

if __name__ == "__main__":
    asyncio.run(main())
