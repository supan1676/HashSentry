"""
HashSentry CLI & Interactive Interface
========================================
Implements the full UIUX wireframe flow:
- Authorized-use disclaimer
- Interactive menus & hash detection
- Recommended & custom attack strategies
- Rich live progress display with speed, ETA, and Ctrl+C checkpointing
- Strength scoring & multi-format report exports (CSV, JSON, Text)
- Batch auditing mode & session resumption
"""

import argparse
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn

from hashsentry.core.detector import detect_hash_type
from hashsentry.core.hasher import FAST_HASH_PROFILES, normalize_algo_name
from hashsentry.core.prioritizer import GuessPrioritizer
from hashsentry.execution.checkpoint import list_checkpoints, load_checkpoint
from hashsentry.execution.manager import CrackResult, ExecutionManager
from hashsentry.reporting.exporter import (
    build_audit_record,
    export_csv,
    export_json,
    export_text,
    mask_password_display,
)
from hashsentry.reporting.scorer import score_password
from hashsentry.strategies.base import BaseStrategy
from hashsentry.strategies.brute_force import BruteForceStrategy
from hashsentry.strategies.dictionary import DictionaryStrategy
from hashsentry.strategies.mask_hybrid import HybridStrategy, MaskStrategy
from hashsentry.strategies.rules import RulesStrategy

console = Console()

DEFAULT_WORDLIST = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "wordlists",
    "sample_wordlist.txt",
)
LAST_REPORT_FILE = "reports/last_report.txt"


def show_disclaimer() -> None:
    """Display authorized security testing notice."""
    disclaimer_text = (
        "[bold red]LEGAL & ETHICAL NOTICE:[/bold red]\n"
        "This tool is strictly for authorized security auditing, educational research, "
        "and penetration testing on systems and hashes you own or have explicit permission to test.\n"
        "[dim]By continuing, you confirm you have proper authorization.[/dim]"
    )
    console.print(
        Panel(
            disclaimer_text,
            title="[bold yellow]HashSentry — Password Hash Security Auditing Tool[/bold yellow]",
            border_style="cyan",
        )
    )


def prompt_hash_and_algo(
    pre_hash: Optional[str] = None, pre_algo: Optional[str] = None
) -> Tuple[str, str]:
    """Prompt for hash and detect/confirm algorithm."""
    target_hash = pre_hash
    while not target_hash:
        target_hash = console.input("\n[bold cyan]Enter target hash:[/bold cyan] ").strip()
        if not target_hash:
            console.print("[red]Hash cannot be empty.[/red]")

    detected = detect_hash_type(target_hash)

    console.print("\n[bold]Detection Results:[/bold]")
    for name, conf in detected:
        badge = "[green]HIGH[/green]" if conf == "high" else (f"[yellow]{conf.upper()}[/yellow]" if conf != "none" else "[red]NONE[/red]")
        console.print(f"  • [bold]{name}[/bold] (Confidence: {badge})")

    if pre_algo:
        return target_hash, normalize_algo_name(pre_algo)

    # Prompt selection if ambiguous or user wants to override
    default_algo = detected[0][0].lower().split()[0]
    if default_algo in ("unknown", "salt-separated"):
        default_algo = "sha256"

    # Display menu for ambiguous candidates
    if len(detected) > 1 and detected[0][1] == "ambiguous":
        console.print(f"\n[yellow]Ambiguous hash length ({len(target_hash)} chars).[/yellow] Which algorithm is it?")
        for i, (name, _) in enumerate(detected, 1):
            console.print(f"  {i}) {name}")
        console.print(f"  {len(detected) + 1}) Other / Manual Entry")

        choice = console.input(f"Select option [default 1 - {detected[0][0]}]: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(detected):
            return target_hash, detected[int(choice) - 1][0].lower()
        elif choice.isdigit() and int(choice) == len(detected) + 1:
            manual = console.input("Enter algorithm name (e.g. md5, sha256, bcrypt, argon2): ").strip()
            return target_hash, normalize_algo_name(manual or default_algo)

    confirm = console.input(
        f"\nAlgorithm to use [[bold green]{default_algo}[/bold green]]: "
    ).strip()
    algo = normalize_algo_name(confirm if confirm else default_algo)
    return target_hash, algo


def _get_wordlist_path() -> str:
    """Prompt user for a wordlist path and validate its existence."""
    has_default = os.path.exists(DEFAULT_WORDLIST)
    while True:
        prompt_str = f"Path to wordlist file [[dim]{DEFAULT_WORDLIST}[/dim]]: " if has_default else "Enter path to wordlist file: "
        wl_input = console.input(prompt_str).strip()
        if not wl_input and has_default:
            return DEFAULT_WORDLIST
        if wl_input and os.path.exists(wl_input):
            return wl_input
        console.print("[red]Wordlist file not found. Please enter a valid file path (e.g. wordlist.txt).[/red]")


def build_strategy_interactive() -> Tuple[BaseStrategy, Dict[str, Any], bool]:
    """Interactive strategy selection menu."""
    console.print("\n[bold cyan]Select Attack Strategy:[/bold cyan]")
    console.print("  [bold green]1) Use Recommended[/bold green] (Dictionary + Rules mutation)")
    console.print("  2) Dictionary only (fast wordlist check)")
    console.print("  3) Brute-force only (exhaustive search)")
    console.print("  4) Mask attack (e.g. ?u?l?l?d?d)")
    console.print("  5) Hybrid attack (Dictionary + brute-forced suffix)")

    choice = console.input("\nSelect strategy [default 1]: ").strip() or "1"
    use_prioritizer = False

    if choice == "2":
        wordlist_path = _get_wordlist_path()
        strat = DictionaryStrategy(wordlist=wordlist_path)
        params = {"wordlist": wordlist_path}
    elif choice == "3":
        cs_choice = console.input("Charset (1: a-z0-9, 2: a-z, 3: full printable) [default 1]: ").strip() or "1"
        if cs_choice == "2":
            charset = "abcdefghijklmnopqrstuvwxyz"
        elif cs_choice == "3":
            charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        else:
            charset = "abcdefghijklmnopqrstuvwxyz0123456789"
        max_len = int(console.input("Max password length [default 4]: ").strip() or "4")
        strat = BruteForceStrategy(charset=charset, min_length=1, max_length=max_len)
        params = {"charset": charset, "min_length": 1, "max_length": max_len}
    elif choice == "4":
        mask = console.input("Enter mask (e.g. ?u?l?l?d?d) [default ?u?l?l?d?d]: ").strip() or "?u?l?l?d?d"
        strat = MaskStrategy(mask=mask)
        params = {"mask": mask}
    elif choice == "5":
        wordlist_path = _get_wordlist_path()
        suffix = console.input("Enter suffix mask (e.g. ?d?d?d?d) [default ?d?d?d?d]: ").strip() or "?d?d?d?d"
        strat = HybridStrategy(wordlist=wordlist_path, suffix_mask=suffix)
        params = {"wordlist": wordlist_path, "suffix_mask": suffix}
    else:  # 1 or default
        wordlist_path = _get_wordlist_path()
        strat = RulesStrategy(wordlist=wordlist_path)
        params = {"wordlist": wordlist_path}
        p_choice = console.input("Enable statistical guess prioritization? (y/N): ").strip().lower()
        if p_choice == "y":
            use_prioritizer = True

    return strat, params, use_prioritizer


def run_single_attack(
    target_hash: str,
    algorithm: str,
    strategy: BaseStrategy,
    strategy_params: Dict[str, Any],
    use_prioritizer: bool = False,
    run_id: Optional[str] = None,
    skip_attempts: int = 0,
    initial_elapsed: float = 0.0,
) -> CrackResult:
    """Execute attack with a live Rich progress bar."""
    candidate_stream = strategy.candidates()
    if use_prioritizer:
        prioritizer = GuessPrioritizer(buffer_size=5000)
        candidate_stream = prioritizer.prioritize_stream(candidate_stream)

    est_total = strategy.estimated_total()

    with Progress(
        TextColumn("[bold cyan]•[/bold cyan]"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(complete_style="green", finished_style="bold green"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("• Attempts: {task.fields[attempts]:,}"),
        TextColumn("• Speed: {task.fields[speed]:,.0f} H/s"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=False,
    ) as progress:
        task_id = progress.add_task(
            f"[cyan]Auditing with {strategy.name}...[/cyan]",
            total=est_total,
            completed=skip_attempts,
            attempts=skip_attempts,
            speed=0.0,
        )

        def on_progress(
            attempts: int,
            elapsed: float,
            speed: float,
            last_cand: Optional[str],
            total_est: Optional[int],
        ) -> None:
            progress.update(
                task_id,
                completed=min(attempts, total_est) if total_est else attempts,
                attempts=attempts,
                speed=speed,
            )

        manager = ExecutionManager(progress_callback=on_progress, progress_interval=0.2)
        console.print("[dim]Press Ctrl+C at any time to pause and save session checkpoint.[/dim]\n")

        result = manager.run(
            target_hash=target_hash,
            algorithm=algorithm,
            candidates_generator=candidate_stream,
            strategy_name=strategy.name,
            strategy_params=strategy_params,
            estimated_total=est_total,
            run_id=run_id,
            skip_attempts=skip_attempts,
            initial_elapsed=initial_elapsed,
        )

    return result


def display_result(result: CrackResult, allow_interactive_export: bool = True) -> None:
    """Display result screen matching UIUX specification."""
    if result.interrupted:
        console.print(
            Panel(
                f"[yellow]Execution paused by user.[/yellow]\n"
                f"Progress saved to checkpoint: [bold]{result.checkpoint_file}[/bold]\n"
                f"Resume anytime using Option 3 from the main menu.",
                title="[bold yellow]Session Saved[/bold yellow]",
                border_style="yellow",
            )
        )
        return

    score = score_password(
        result.password,
        strategy_used=result.strategy_name,
        attempts=result.attempts,
        elapsed_seconds=result.elapsed_seconds,
    )

    if result.found:
        table = Table(show_header=False, box=None)
        table.add_row("[bold green]Status:[/bold green]", "[green]Password Recovered[/green]")
        table.add_row("Target Hash:", f"[dim]{result.target_hash}[/dim]")
        table.add_row("Algorithm:", result.algorithm)
        table.add_row("Password (Masked):", f"[bold cyan]{mask_password_display(result.password)}[/bold cyan] [dim](plain in export)[/dim]")
        table.add_row("Strategy:", result.strategy_name)
        table.add_row("Attempts:", f"{result.attempts:,}")
        table.add_row("Elapsed Time:", f"{result.elapsed_seconds:.2f}s  ({result.speed:,.0f} H/s)")
        
        rating_color = "red" if score.rating in ("CRITICAL", "WEAK") else ("yellow" if score.rating == "MODERATE" else "green")
        table.add_row("Security Strength:", f"[{rating_color}][bold]{score.rating}[/bold] (Score: {score.score}/100)[/{rating_color}]")
        table.add_row("Assessment:", score.reasoning)
        if score.detected_patterns:
            table.add_row("Patterns:", ", ".join(score.detected_patterns))
        if score.policy_violations:
            table.add_row("Policy Violations:", f"[red]{'; '.join(score.policy_violations)}[/red]")

        console.print(Panel(table, title="[bold green][OK] Hash Audit Result[/bold green]", border_style="green"))

    else:
        table = Table(show_header=False, box=None)
        table.add_row("[bold red]Status:[/bold red]", "[red]Not Recovered within current settings[/red]")
        table.add_row("Target Hash:", f"[dim]{result.target_hash}[/dim]")
        table.add_row("Algorithm:", result.algorithm)
        table.add_row("Strategy:", result.strategy_name)
        table.add_row("Attempts:", f"{result.attempts:,}")
        table.add_row("Elapsed Time:", f"{result.elapsed_seconds:.2f}s  ({result.speed:,.0f} H/s)")
        table.add_row("Recommendations:", "Try a larger charset, longer max length, or expanded wordlist.")
        console.print(Panel(table, title="[bold red][X] Hash Audit Result[/bold red]", border_style="red"))

    # Offer export only when interactive prompt is desired
    if allow_interactive_export:
        prompt_export([result])


def prompt_export(results: List[CrackResult]) -> None:
    """Prompt user to export results to CSV, JSON, or Text report."""
    exp = console.input("\nExport audit report? (c=CSV, j=JSON, t=Text, n=No) [n]: ").strip().lower()
    if exp in ("c", "csv"):
        path = console.input("Save CSV path [reports/audit_report.csv]: ").strip() or "reports/audit_report.csv"
        records = [build_audit_record(r) for r in results]
        out = export_csv(records, path)
        console.print(f"[bold green]✓ CSV report saved to:[/bold green] {out}")
    elif exp in ("j", "json"):
        path = console.input("Save JSON path [reports/audit_report.json]: ").strip() or "reports/audit_report.json"
        records = [build_audit_record(r) for r in results]
        out = export_json(records, path)
        console.print(f"[bold green]✓ JSON report saved to:[/bold green] {out}")
    elif exp in ("t", "txt", "y", "text"):
        path = console.input("Save Text report path [reports/audit_report.txt]: ").strip() or "reports/audit_report.txt"
        records = [build_audit_record(r) for r in results]
        out = export_text(records, path)
        # Also cache as last report
        export_text(records, LAST_REPORT_FILE)
        console.print(f"[bold green]✓ Text report saved to:[/bold green] {out}")


def batch_audit_flow() -> None:
    """Batch mode: audit multiple hashes from a file or user input."""
    console.print("\n[bold cyan]=== Batch Hash Audit ===[/bold cyan]")
    path = console.input("Enter path to file containing hashes (one per line): ").strip()
    if not os.path.exists(path):
        console.print(f"[red]File not found: {path}[/red]")
        return

    hashes: List[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            h = line.strip()
            if h and not h.startswith("#"):
                hashes.append(h)

    if not hashes:
        console.print("[yellow]No hashes found in file.[/yellow]")
        return

    console.print(f"Loaded [bold green]{len(hashes)}[/bold green] hashes.")
    default_algo = detect_hash_type(hashes[0])[0][0].lower().split()[0]
    if default_algo in ("unknown", "salt-separated"):
        default_algo = "sha256"

    algo_input = console.input(f"Algorithm for batch [[bold green]{default_algo}[/bold green]]: ").strip()
    algorithm = normalize_algo_name(algo_input if algo_input else default_algo)

    strategy, params, use_prio = build_strategy_interactive()

    results: List[CrackResult] = []
    console.print(f"\n[bold]Starting batch audit of {len(hashes)} hashes...[/bold]")

    for idx, h in enumerate(hashes, 1):
        console.print(f"\n[bold]Processing [{idx}/{len(hashes)}]:[/bold] {h[:32]}...")
        res = run_single_attack(
            target_hash=h,
            algorithm=algorithm,
            strategy=strategy,
            strategy_params=params,
            use_prioritizer=use_prio,
        )
        results.append(res)
        if res.interrupted:
            console.print("[yellow]Batch interrupted by user.[/yellow]")
            break

    # Summary table
    cracked_count = sum(1 for r in results if r.found)
    total_count = len(results)
    pct = (cracked_count / total_count * 100) if total_count > 0 else 0.0

    summary_table = Table(title="[bold green]Batch Audit Summary[/bold green]")
    summary_table.add_column("Metric", style="bold")
    summary_table.add_column("Value", style="cyan")
    summary_table.add_row("Total Hashes Processed", str(total_count))
    summary_table.add_row("Successfully Recovered", f"{cracked_count} ({pct:.1f}%)")
    summary_table.add_row("Unrecovered", str(total_count - cracked_count))

    console.print(summary_table)

    # Save default batch report
    default_csv = f"reports/batch_audit_{int(time.time())}.csv"
    records = [build_audit_record(r) for r in results]
    export_csv(records, default_csv)
    export_text(records, LAST_REPORT_FILE)
    console.print(f"[bold green]✓ Full batch audit CSV automatically saved to:[/bold green] {default_csv}")
    prompt_export(results)


def resume_session_flow() -> None:
    """Resume a previously checkpointed session."""
    checkpoints = list_checkpoints()
    if not checkpoints:
        console.print("[yellow]No saved sessions found.[/yellow]")
        return

    table = Table(title="[bold cyan]Saved Checkpoint Sessions[/bold cyan]")
    table.add_column("#", justify="right")
    table.add_column("Run ID", style="bold")
    table.add_column("Date Saved")
    table.add_column("Algorithm")
    table.add_column("Strategy")
    table.add_column("Attempts So Far")

    for i, cp in enumerate(checkpoints, 1):
        table.add_row(
            str(i),
            cp.get("run_id", "unknown"),
            cp.get("date_saved", "unknown"),
            cp.get("algorithm", "unknown"),
            cp.get("strategy_name", "unknown"),
            f"{cp.get('attempts', 0):,}",
        )

    console.print(table)
    choice = console.input("\nSelect session to resume (number) or [q] to cancel: ").strip()
    if choice.lower() == "q" or not choice.isdigit():
        return

    idx = int(choice) - 1
    if not (0 <= idx < len(checkpoints)):
        console.print("[red]Invalid selection.[/red]")
        return

    cp = checkpoints[idx]
    run_id = cp["run_id"]
    target_hash = cp["target_hash"]
    algorithm = cp["algorithm"]
    strat_name = cp["strategy_name"]
    params = cp.get("strategy_params", {})
    attempts = cp.get("attempts", 0)
    elapsed = cp.get("elapsed_seconds", 0.0)

    # Reconstruct strategy
    if "Mask" in strat_name:
        strategy = MaskStrategy(mask=params.get("mask", "?u?l?l?d?d"))
    elif "Hybrid" in strat_name:
        strategy = HybridStrategy(
            wordlist=params.get("wordlist", DEFAULT_WORDLIST),
            suffix_mask=params.get("suffix_mask", "?d?d?d?d"),
        )
    elif "Rules" in strat_name or "mutat" in strat_name.lower():
        strategy = RulesStrategy(wordlist=params.get("wordlist", DEFAULT_WORDLIST))
    elif "Dictionary" in strat_name:
        strategy = DictionaryStrategy(wordlist=params.get("wordlist", DEFAULT_WORDLIST))
    else:
        strategy = BruteForceStrategy(
            charset=params.get("charset", "abcdefghijklmnopqrstuvwxyz0123456789"),
            min_length=params.get("min_length", 1),
            max_length=params.get("max_length", 4),
        )

    console.print(f"\n[bold green]Resuming {run_id} from {attempts:,} attempts...[/bold green]")
    res = run_single_attack(
        target_hash=target_hash,
        algorithm=algorithm,
        strategy=strategy,
        strategy_params=params,
        run_id=run_id,
        skip_attempts=attempts,
        initial_elapsed=elapsed,
    )
    display_result(res)


def view_last_report() -> None:
    """View the most recent audit report in terminal."""
    if os.path.exists(LAST_REPORT_FILE):
        with open(LAST_REPORT_FILE, "r", encoding="utf-8") as f:
            content = f.read()
        console.print(Panel(content, title="[bold cyan]Last Audit Report[/bold cyan]", border_style="cyan"))
    else:
        console.print("[yellow]No recent report found. Run an audit first.[/yellow]")


def run_demo() -> None:
    """Run an automated demo showcasing hash detection, rules, mask, and hybrid attacks."""
    console.print(Panel("[bold yellow]Running HashSentry Feature Demonstration[/bold yellow]"))

    samples = [
        "72c430cbf240a47a9f7d9a7d6a6fc36a",
        "fd1fa8af619ee320f1fab31824616394cc62716a",
        "$2b$12$KIXQ7hR8mF3n9qzXO5tYbeh2sN0V8pR1cL4jW6xT9",
        "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdN3ub",
    ]
    console.print("[bold cyan]1. Hash Type Auto-Detection:[/bold cyan]")
    for s in samples:
        res = detect_hash_type(s)
        names = ", ".join(f"{n} ({c})" for n, c in res)
        console.print(f"  {s[:36]}...  ->  [bold]{names}[/bold]")

    console.print("\n[bold cyan]2. Dictionary + Rules Attack on MD5 ('Football2025'):[/bold cyan]")
    from hashsentry.core.hasher import hash_password
    target = hash_password("Football2025", "md5")
    if os.path.exists(DEFAULT_WORDLIST):
        strat = RulesStrategy(wordlist=DEFAULT_WORDLIST)
    else:
        strat = RulesStrategy(wordlist=["football", "password", "admin", "dragon", "shadow", "sunshine"])
    manager = ExecutionManager()
    res = manager.run(target, "md5", strat.candidates(), strategy_name=strat.name)
    display_result(res, allow_interactive_export=False)


def interactive_main() -> None:
    """Main interactive menu driver matching UIUX specification."""
    show_disclaimer()

    while True:
        console.print("\n" + "=" * 50)
        console.print("  [bold cyan]HashSentry[/bold cyan] - Main Menu")
        console.print("=" * 50)
        console.print("  [bold]1)[/bold] Crack a single hash")
        console.print("  [bold]2)[/bold] Batch audit (multiple hashes)")
        console.print("  [bold]3)[/bold] Resume a previous session")
        console.print("  [bold]4)[/bold] View last report")
        console.print("  [bold]5)[/bold] Run quick demo")
        console.print("  [bold]6)[/bold] Exit")
        console.print("-" * 50)

        choice = console.input("Select an option [1-6]: ").strip()

        if choice == "1":
            target_hash, algo = prompt_hash_and_algo()
            strategy, params, use_prio = build_strategy_interactive()
            result = run_single_attack(
                target_hash=target_hash,
                algorithm=algo,
                strategy=strategy,
                strategy_params=params,
                use_prioritizer=use_prio,
            )
            display_result(result)

        elif choice == "2":
            batch_audit_flow()

        elif choice == "3":
            resume_session_flow()

        elif choice == "4":
            view_last_report()

        elif choice == "5":
            run_demo()

        elif choice in ("6", "q", "exit"):
            console.print("[dim]Exiting HashSentry. Stay safe.[/dim]")
            break
        else:
            console.print("[red]Invalid selection. Please choose 1-6.[/red]")


def parse_args() -> argparse.Namespace:
    """Parse CLI command line arguments for headless/automated execution."""
    parser = argparse.ArgumentParser(description="HashSentry — Password Hash Security Auditing Tool")
    parser.add_argument("-t", "--target", help="Target password hash")
    parser.add_argument("-a", "--algo", help="Algorithm (md5, sha1, sha256, sha512, bcrypt, argon2, ntlm, etc.)")
    parser.add_argument("-m", "--mode", choices=["rules", "dictionary", "brute", "mask", "hybrid"], help="Attack mode")
    parser.add_argument("-w", "--wordlist", default=DEFAULT_WORDLIST, help="Path to wordlist file")
    parser.add_argument("--mask", default="?u?l?l?d?d", help="Mask for mask/hybrid attack")
    parser.add_argument("--charset", default="abcdefghijklmnopqrstuvwxyz0123456789", help="Charset for brute-force")
    parser.add_argument("--max-length", type=int, default=4, help="Max length for brute-force")
    parser.add_argument("--prioritize", action="store_true", help="Enable frequency-based candidate prioritization")
    parser.add_argument("--batch", help="Path to file containing hashes for batch audit")
    parser.add_argument("--export-csv", help="Save output directly to CSV file")
    parser.add_argument("--export-json", help="Save output directly to JSON file")
    parser.add_argument("--demo", action="store_true", help="Run automated demonstration")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.demo:
        show_disclaimer()
        run_demo()
        return

    if args.target:
        show_disclaimer()
        target_hash = args.target
        algo = normalize_algo_name(args.algo if args.algo else detect_hash_type(target_hash)[0][0].split()[0])
        mode = args.mode or "rules"

        if mode == "dictionary":
            strategy = DictionaryStrategy(wordlist=args.wordlist)
            params = {"wordlist": args.wordlist}
        elif mode == "brute":
            strategy = BruteForceStrategy(charset=args.charset, max_length=args.max_length)
            params = {"charset": args.charset, "max_length": args.max_length}
        elif mode == "mask":
            strategy = MaskStrategy(mask=args.mask)
            params = {"mask": args.mask}
        elif mode == "hybrid":
            strategy = HybridStrategy(wordlist=args.wordlist, suffix_mask=args.mask)
            params = {"wordlist": args.wordlist, "suffix_mask": args.mask}
        else:
            strategy = RulesStrategy(wordlist=args.wordlist)
            params = {"wordlist": args.wordlist}

        result = run_single_attack(
            target_hash=target_hash,
            algorithm=algo,
            strategy=strategy,
            strategy_params=params,
            use_prioritizer=args.prioritize,
        )
        has_cli_export = bool(args.export_csv or args.export_json)
        display_result(result, allow_interactive_export=not has_cli_export)

        if args.export_csv:
            export_csv([build_audit_record(result)], args.export_csv)
            console.print(f"[bold green]Saved CSV to {args.export_csv}[/bold green]")
        if args.export_json:
            export_json([build_audit_record(result)], args.export_json)
            console.print(f"[bold green]Saved JSON to {args.export_json}[/bold green]")
        return

    # Default to interactive menu
    interactive_main()


if __name__ == "__main__":
    main()
