"""
Token usage and performance tracking utility for LLM API calls.
"""
from typing import Dict, List, Optional, Any
import json
import time
from datetime import datetime
import re
import os

class PerformanceTracker:
    """
    Performance tracker for the system that tracks:
    - Token usage by agent and model
    - Line count of analyzed code
    - Time taken for each stage of processing
    - Total run time
    """

    def __init__(self):
        self.reset()
    
    def reset(self):
        """Reset all performance metrics."""
        # Token tracking
        self.usage_by_agent = {}
        self.usage_by_model = {}
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_tokens = 0
        self.call_count = 0
        
        # Code metrics
        self.total_lines = 0
        self.contract_files = []
        
        # Time tracking
        self.start_time = time.time()
        self.stage_times = {}
        self.current_stage = None
        self.current_stage_start = None
        
        # Run metadata
        self.run_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.run_config = {}
    
    def log_tokens(self, 
                  agent_name: str, 
                  model_name: str, 
                  prompt_tokens: int, 
                  completion_tokens: int, 
                  total_tokens: int):
        """
        Log token usage for a specific agent and model.
        
        Args:
            agent_name: Name of the agent making the call
            model_name: Name of the model used
            prompt_tokens: Number of tokens in the prompt
            completion_tokens: Number of tokens in the completion
            total_tokens: Total number of tokens used
        """
        # Update agent-specific counts
        if agent_name not in self.usage_by_agent:
            self.usage_by_agent[agent_name] = {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
                "call_count": 0
            }
        
        self.usage_by_agent[agent_name]["prompt_tokens"] += prompt_tokens
        self.usage_by_agent[agent_name]["completion_tokens"] += completion_tokens
        self.usage_by_agent[agent_name]["total_tokens"] += total_tokens
        self.usage_by_agent[agent_name]["call_count"] += 1
        
        # Update model-specific counts
        if model_name not in self.usage_by_model:
            self.usage_by_model[model_name] = {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
                "call_count": 0
            }
        
        self.usage_by_model[model_name]["prompt_tokens"] += prompt_tokens
        self.usage_by_model[model_name]["completion_tokens"] += completion_tokens
        self.usage_by_model[model_name]["total_tokens"] += total_tokens
        self.usage_by_model[model_name]["call_count"] += 1
        
        # Update total counts
        self.total_prompt_tokens += prompt_tokens
        self.total_completion_tokens += completion_tokens
        self.total_tokens += total_tokens
        self.call_count += 1
    
    def log_code_analysis(self, file_paths: List[str]):
        """
        Log information about the code being analyzed.
        
        Args:
            file_paths: List of file paths that were analyzed
        """
        self.contract_files = file_paths
        
        # Count total lines
        total_lines = 0
        for file_path in file_paths:
            if os.path.exists(file_path) and file_path.endswith('.sol'):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        # Count non-empty lines
                        lines = [line for line in content.split('\n') if line.strip()]
                        total_lines += len(lines)
                except Exception as e:
                    print(f"Warning: Could not count lines in {file_path}: {e}")
        
        self.total_lines = total_lines
    
    def start_stage(self, stage_name: str):
        """
        Start timing a new stage of processing.
        
        Args:
            stage_name: Name of the stage to track
        """
        # If there's a current stage, end it first
        if self.current_stage is not None:
            self.end_stage()
        
        self.current_stage = stage_name
        self.current_stage_start = time.time()
    
    def end_stage(self):
        """End timing the current stage."""
        if self.current_stage is None or self.current_stage_start is None:
            return
        
        elapsed = time.time() - self.current_stage_start
        
        if self.current_stage in self.stage_times:
            self.stage_times[self.current_stage] += elapsed
        else:
            self.stage_times[self.current_stage] = elapsed
        
        self.current_stage = None
        self.current_stage_start = None
    
    def set_run_config(self, config: Dict[str, Any]):
        """
        Set the configuration information for this run.
        
        Args:
            config: Dictionary with configuration parameters
        """
        self.run_config = config
    
    def get_performance_summary(self) -> Dict:
        """
        Get a summary of all performance metrics.
        
        Returns:
            Dictionary with all performance metrics
        """
        # End any current stage
        if self.current_stage is not None:
            self.end_stage()
        
        # Calculate total elapsed time
        total_time = time.time() - self.start_time
        
        # Calculate derived metrics
        tokens_per_second = self.total_tokens / total_time if total_time > 0 else 0
        tokens_per_loc = self.total_tokens / self.total_lines if self.total_lines > 0 else 0
        
        return {
            "run_info": {
                "timestamp": self.run_timestamp,
                "config": self.run_config,
                "total_time_seconds": total_time
            },
            "token_usage": {
                "by_agent": self.usage_by_agent,
                "by_model": self.usage_by_model,
                "total": {
                    "prompt_tokens": self.total_prompt_tokens,
                    "completion_tokens": self.total_completion_tokens,
                    "total_tokens": self.total_tokens,
                    "call_count": self.call_count
                }
            },
            "code_metrics": {
                "total_lines": self.total_lines,
                "file_count": len(self.contract_files),
                "files": self.contract_files
            },
            "time_metrics": {
                "total_seconds": total_time,
                "stage_times": self.stage_times
            },
            "derived_metrics": {
                "tokens_per_second": tokens_per_second,
                "tokens_per_loc": tokens_per_loc
            }
        }
    
    def save_to_file(self, filepath: Optional[str] = None) -> str:
        """
        Save performance metrics to a JSON file.
        
        Args:
            filepath: Optional path to save the file. If not provided,
                     a default path will be used.
                     
        Returns:
            Path where the file was saved
        """
        import os
        if filepath is None:
            dir_path = "performance_analysis"
            os.makedirs(dir_path, exist_ok=True)
            filepath = os.path.join(dir_path, f"performance_metrics_{self.run_timestamp}.json")
        else:
            dir_name = os.path.dirname(filepath)
            if dir_name:
                os.makedirs(dir_name, exist_ok=True)
        
        with open(filepath, 'w') as f:
            json.dump(self.get_performance_summary(), f, indent=2)
        
        return filepath
    
    def print_summary(self, include_detailed_breakdowns: bool = False):
        """
        Print a formatted summary of performance metrics.
        
        Args:
            include_detailed_breakdowns: Whether to include detailed breakdowns by agent and model
        """
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        
        console = Console()
        
        # Get the performance summary
        summary = self.get_performance_summary()
        
        # Print the main summary table
        main_table = Table(title="Performance Summary", show_header=True)
        
        # Add columns for the main metrics
        main_table.add_column("Metric", style="cyan")
        main_table.add_column("Value", style="green")
        
        # Add the most important metrics to the table
        main_table.add_row("Total Run Time", f"{summary['run_info']['total_time_seconds']:.2f} seconds")
        main_table.add_row("Total Tokens Used", f"{summary['token_usage']['total']['total_tokens']:,}")
        main_table.add_row("Lines of Code Analyzed", f"{summary['code_metrics']['total_lines']:,}")
        main_table.add_row("Contract Files", f"{summary['code_metrics']['file_count']}")
        main_table.add_row("Tokens per Second", f"{summary['derived_metrics']['tokens_per_second']:.2f}")
        main_table.add_row("Tokens per LOC", f"{summary['derived_metrics']['tokens_per_loc']:.2f}")
        
        console.print(Panel(main_table, title="[bold blue]Performance Metrics[/bold blue]", 
                            subtitle=f"Run timestamp: {summary['run_info']['timestamp']}"))
        
        # Print the time breakdown
        time_table = Table(title="Time by Stage", show_header=True)
        time_table.add_column("Stage", style="cyan")
        time_table.add_column("Time (seconds)", style="green")
        time_table.add_column("Percentage", style="yellow")
        
        # Sort stages by time (descending)
        sorted_stages = sorted(summary['time_metrics']['stage_times'].items(), 
                              key=lambda x: x[1], reverse=True)
        
        total_time = summary['time_metrics']['total_seconds']
        
        for stage, time_sec in sorted_stages:
            percentage = (time_sec / total_time) * 100 if total_time > 0 else 0
            time_table.add_row(stage, f"{time_sec:.2f}", f"{percentage:.1f}%")
        
        console.print(Panel(time_table, title="[bold blue]Time Breakdown[/bold blue]"))
        
        # Print detailed breakdowns if requested
        if include_detailed_breakdowns:
            # Token usage by agent
            agent_table = Table(title="Token Usage by Agent", show_header=True)
            agent_table.add_column("Agent")
            agent_table.add_column("Calls")
            agent_table.add_column("Prompt Tokens")
            agent_table.add_column("Completion Tokens")
            agent_table.add_column("Total Tokens")
            
            for agent, usage in summary['token_usage']['by_agent'].items():
                agent_table.add_row(
                    agent,
                    str(usage["call_count"]),
                    f"{usage['prompt_tokens']:,}",
                    f"{usage['completion_tokens']:,}",
                    f"{usage['total_tokens']:,}"
                )
            
            console.print(Panel(agent_table, title="[bold blue]Agent Token Usage[/bold blue]"))
            
            # Token usage by model
            model_table = Table(title="Token Usage by Model", show_header=True)
            model_table.add_column("Model")
            model_table.add_column("Calls")
            model_table.add_column("Prompt Tokens")
            model_table.add_column("Completion Tokens")
            model_table.add_column("Total Tokens")
            
            for model, usage in summary['token_usage']['by_model'].items():
                model_table.add_row(
                    model,
                    str(usage["call_count"]),
                    f"{usage['prompt_tokens']:,}",
                    f"{usage['completion_tokens']:,}",
                    f"{usage['total_tokens']:,}"
                )
            
            console.print(Panel(model_table, title="[bold blue]Model Token Usage[/bold blue]"))
        
        # Print a note about saved metrics
        results_file = f"performance_metrics_{summary['run_info']['timestamp']}.json"
        console.print(f"[dim]Performance metrics saved to: {results_file}[/dim]")


# Backwards compatibility for the old TokenTracker API
class TokenTracker(PerformanceTracker):
    """
    Token usage tracker for OpenAI and other LLM API calls.
    Tracks prompt tokens, completion tokens, and total tokens used
    by different components of the system.
    
    This class extends PerformanceTracker for backwards compatibility.
    """
    
    def get_usage_summary(self) -> Dict:
        """
        Get a summary of token usage.
        
        Returns:
            Dictionary with token usage summary
        """
        summary = self.get_performance_summary()
        return {
            "by_agent": summary["token_usage"]["by_agent"],
            "by_model": summary["token_usage"]["by_model"],
            "total": summary["token_usage"]["total"],
            "timestamp": summary["run_info"]["timestamp"]
        }


# Global instance for use throughout the application
# Use a single TokenTracker instance for both interfaces for backward compatibility
performance_tracker = TokenTracker()  # This is the primary tracker used throughout the app
token_tracker = performance_tracker   # This ensures both point to the same object