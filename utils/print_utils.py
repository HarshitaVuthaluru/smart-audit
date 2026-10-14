# utils/print_utils.py
import sys
import time
from typing import Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

# Windows terminals and redirected output can default to cp1252, which cannot
# render the status symbols used throughout the CLI.  Configure text streams
# once before Rich (or any local Console instances) writes to them.
for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

console = Console(legacy_windows=False)

def print_header(text: str):
    """Print a section header with formatting"""
    console.print(f"\n[bold blue]== {text} ==[/bold blue]")

def print_step(text: str):
    """Print a step indicator"""
    console.print(f"[green]→[/green] {text}")

def print_warning(text: str):
    """Print a warning message"""
    console.print(f"[yellow]⚠ {text}[/yellow]")

def print_error(text: str):
    """Print an error message"""
    console.print(f"[red]✗ {text}[/red]")

def print_success(text: str):
    """Print a success message"""
    console.print(f"[green]✓ {text}[/green]")

def create_progress_spinner(text: str) -> Progress:
    """Create a spinner progress bar"""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console
    )

def create_progress_bar(text: str) -> Progress:
    """Create a standard progress bar"""
    return Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    )
