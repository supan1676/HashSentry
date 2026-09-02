"""
HashSentry CLI & Interactive Interface
========================================
Implements the full UIUX flow with pure in-memory streaming candidate generation:
- Authorized-use disclaimer
- Interactive menus & hash detection
- Dynamic Pattern expansion (O(1) memory streaming) & custom attack strategies
- Rich live progress display with speed, ETA, and Ctrl+C checkpointing
- Strength scoring & multi-format report exports (CSV, JSON, Text)
- Batch auditing mode & session resumption
"""

import argparse
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn

from hashsentry.core.detector import detect_hash_type
from hashsentry.core.hasher import normalize_algo_name
from hashsentry.core.prioritizer import GuessPrioritizer
from hashsentry.execution.checkpoint import list_checkpoints
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
from hashsentry.strategies.mask_hybrid import HybridStrategy, MaskStrategy
from hashsentry.strategies.pattern import (
    CHARSET_ALL_PRINTABLE,
    CHARSET_ALPHANUMERIC,
    CHARSET_DIGITS,
    CHARSET_LETTERS,
    CHARSET_LOWER_NUM,
    CHARSET_SYMBOLS,
    PatternStrategy,
)
from hashsentry.strategies.rules import RulesStrategy

console = Console()
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


def build_strategy_interactive() -> Tuple[BaseStrategy, Dict[str, Any], bool]:
    """Interactive strategy selection menu."""
    console.print("\n[bold cyan]Select Attack Strategy:[/bold cyan]")
    console.print("  [bold green]1) Pattern & Combinatorial Stream[/bold green] (Optional base prefix + streaming A-Z, a-z, 0-9, symbols)")
    console.print("  2) Mask attack (e.g. ?u?l?l?d?d, bante?a)")
    console.print("  3) Smart Human Mutations (In-memory rule mutations on root patterns)")
    console.print("  4) Exhaustive Brute-force (Full length & charset search)")
    console.print("  5) Hybrid attack (Base word + Mask suffix)")

    choice = console.input("\nSelect strategy [default 1]: ").strip() or "1"
    use_prioritizer = False

    if choice == "2":
        mask = console.input("Enter mask (e.g. ?u?l?l?d?d or bante?a) [default ?u?l?l?d?d]: ").strip() or "?u?l?l?d?d"
        strat = MaskStrategy(mask=mask)
        params = {"mask": mask}
    elif choice == "3":
        base = console.input("Enter base seed word(s) (e.g. 'admin' or leave blank for default seeds): ").strip()
        strat = RulesStrategy(base_words=base if base else None)
        params = {"base_words": base}
        p_choice = console.input("Enable statistical guess prioritization? (y/N): ").strip().lower()
        if p_choice == "y":
            use_prioritizer = True
    elif choice == "4":
        console.print("\nSelect character set for brute-force:")
        console.print("  1) Lowercase + Digits (a-z0-9) [default]")
        console.print("  2) Lowercase letters only (a-z)")
        console.print("  3) Full 94 Printable ASCII (A-Z, a-z, 0-9, symbols)")
        cs_choice = console.input("Select charset [default 1]: ").strip() or "1"
        if cs_choice == "2":
            charset = "abcdefghijklmnopqrstuvwxyz"
        elif cs_choice == "3":
            charset = CHARSET_ALL_PRINTABLE
        else:
            charset = CHARSET_LOWER_NUM
        max_len = int(console.input("Max password length [default 4]: ").strip() or "4")
        strat = BruteForceStrategy(charset=charset, min_length=1, max_length=max_len)
        params = {"charset": charset, "min_length": 1, "max_length": max_len}
    elif choice == "5":
        base = console.input("Enter base word (e.g. 'admin'): ").strip() or "admin"
        suffix = console.input("Enter suffix mask (e.g. ?d?d?d?d) [default ?d?d?d?d]: ").strip() or "?d?d?d?d"
        strat = HybridStrategy(base_words=base, suffix_mask=suffix)
        params = {"base_words": base, "suffix_mask": suffix}
    else:  # 1 or default (Pattern Strategy)
        base_prefix = console.input("Enter base prefix (e.g. 'bante' or press Enter if none): ").strip()
        console.print("\nSelect character set for combinations:")
        console.print("  [bold green]1) All 94 Printable ASCII[/bold green] (A-Z, a-z, 0-9, special symbols) [default]")
        console.print("  2) Alphanumeric (A-Z, a-z, 0-9)")
        console.print("  3) Lowercase + Digits (a-z, 0-9)")
        console.print("  4) Letters only (A-Z, a-z)")
        console.print("  5) Digits only (0-9)")
        cs_sel = console.input("Select charset [default 1]: ").strip() or "1"

        if cs_sel == "2":
            charset = CHARSET_ALPHANUMERIC
        elif cs_sel == "3":
            charset = CHARSET_LOWER_NUM
        elif cs_sel == "4":
            charset = CHARSET_LETTERS
        elif cs_sel == "5":
            charset = CHARSET_DIGITS
        else:
            charset = CHARSET_ALL_PRINTABLE

        min_s = int(console.input("Min suffix length [default 1]: ").strip() or "1")
        max_s = int(console.input("Max suffix length [default 2]: ").strip() or "2")
        strat = PatternStrategy(
            base_prefix=base_prefix,
            charset=charset,
            min_suffix_len=min_s,
            max_suffix_len=max_s,
        )
        params = {
            "base_prefix": base_prefix,
            "charset": charset,
            "min_suffix_len": min_s,
            "max_suffix_len": max_s,
        }

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
    """Execute a single hash attack run with live Rich progress UI."""
    candidates = strategy.candidates()

    if use_prioritizer:
        prioritizer = GuessPrioritizer()
        candidates = prioritizer.prioritize_stream(candidates)

    console.print("\n[dim]Press Ctrl+C at any time to pause and save session checkpoint.[/dim]\n")

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
            f"Auditing with [bold]{strategy.name}[/bold]...",
            total=est_total,
            attempts=skip_attempts,
            speed=0.0,
        )

        def on_progress(attempts: int, elapsed: float, speed: float, last_cand: Optional[str], est_total_val: Optional[int]) -> None:
            completed_val = min(attempts, est_total) if est_total else attempts
            progress.update(
                task_id,
                completed=completed_val,
                attempts=attempts,
                speed=speed,
            )

        manager = ExecutionManager(progress_callback=on_progress)
        result = manager.run(
            target_hash=target_hash,
            algorithm=algorithm,
            candidates_generator=candidates,
            strategy_name=strategy.name,
            strategy_params=strategy_params,
            estimated_total=est_total,
            run_id=run_id,
            skip_attempts=skip_attempts,
            initial_elapsed=initial_elapsed,
        )

    return result


def display_result(result: CrackResult, allow_interactive_export: bool = True) -> None:
    """Display clean Rich audit outcome card matching UIUX specification."""
    score = score_password(
        result.password,
        strategy_used=result.strategy_name,
        attempts=result.attempts,
        elapsed_seconds=result.elapsed_seconds,
    )

    if result.found:
        title = "[bold green][OK] Hash Audit Result[/bold green]"
        status_text = "[bold green]Password Recovered[/bold green]"
        masked = mask_password_display(result.password)
    elif result.interrupted:
        title = "[bold yellow][PAUSED] Session Checkpointed[/bold yellow]"
        status_text = "[bold yellow]Interrupted & Saved[/bold yellow]"
        masked = "<session paused>"
    else:
        title = "[bold red][X] Hash Audit Result[/bold red]"
        status_text = "[bold red]Not Recovered within current settings[/bold red]"
        masked = "<not recovered>"

    # Render audit details table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold cyan", width=20)
    table.add_column("Value")

    table.add_row("Status:", status_text)
    table.add_row("Target Hash:", result.target_hash)
    table.add_row("Algorithm:", result.algorithm)
    table.add_row("Password (Masked):", f"{masked} [dim](plain in export)[/dim]" if result.found else masked)
    table.add_row("Strategy:", result.strategy_name)
    table.add_row("Attempts:", f"{result.attempts:,}")
    table.add_row("Elapsed Time:", f"{result.elapsed_seconds:.2f}s  [dim]({result.speed:,.0f} H/s)[/dim]")

    if result.found:
        color = "red" if score.rating == "CRITICAL" else ("yellow" if score.rating == "WEAK" else "green")
        table.add_row("Security Strength:", f"[{color}]{score.rating}[/{color}] (Score: {score.score}/100)")
        if score.detected_patterns:
            table.add_row("Patterns Found:", ", ".join(score.detected_patterns))
        table.add_row("Assessment:", score.reasoning)
        if score.policy_violations:
            table.add_row("Policy Violations:", "; ".join(score.policy_violations))
    elif result.interrupted:
        table.add_row("Run ID:", result.run_id or "")
        table.add_row("Checkpoint:", f"[dim]{result.checkpoint_file}[/dim]")
        table.add_row("Resume With:", f"python run.py (Menu option 3)")
    else:
        table.add_row("Recommendations:", "Try a larger charset, longer max length, or token masks.")

    console.print(Panel(table, title=title, border_style="green" if result.found else ("yellow" if result.interrupted else "red")))

    # Auto-save last text report
    record = build_audit_record(result, score)
    export_text([record], LAST_REPORT_FILE)

    if allow_interactive_export:
        prompt_export([result])


def prompt_export(results: List[CrackResult]) -> None:
    """Prompt user to export findings to CSV, JSON, or Text report."""
    choice = console.input("\nExport audit report? ([bold]c[/bold]=CSV, [bold]j[/bold]=JSON, [bold]t[/bold]=Text, [bold]n[/bold]=No) : ").strip().lower()
    if not choice or choice == "n":
        return

    os.makedirs("reports", exist_ok=True)
    ts = int(time.time())
    records = [build_audit_record(r) for r in results]

    if choice == "c":
        path = f"reports/audit_report_{ts}.csv"
        export_csv(records, path)
        console.print(f"[bold green]Saved CSV report to:[/bold green] {path}")
    elif choice == "j":
        path = f"reports/audit_report_{ts}.json"
        export_json(records, path)
        console.print(f"[bold green]Saved JSON report to:[/bold green] {path}")
    elif choice == "t":
        path = f"reports/audit_report_{ts}.txt"
        export_text(records, path)
        console.print(f"[bold green]Saved Text report to:[/bold green] {path}")


def batch_audit_flow() -> None:
    """Execute batch audit from input file of hashes."""
    filepath = console.input("Path to hash file (one per line): ").strip()
    if not os.path.exists(filepath):
        console.print("[red]File not found.[/red]")
        return

    hashes = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            h = line.strip()
            if h and not h.startswith("#"):
                hashes.append(h)

    if not hashes:
        console.print("[yellow]No hashes found in file.[/yellow]")
        return

    console.print(f"\n[bold green]Loaded {len(hashes)} target hashes.[/bold green]")
    strategy, params, use_prio = build_strategy_interactive()

    results: List[CrackResult] = []
    start_time = time.time()

    for idx, target_hash in enumerate(hashes, 1):
        detected = detect_hash_type(target_hash)
        algo = detected[0][0].lower().split()[0]
        if algo in ("unknown", "salt-separated"):
            algo = "sha256"

        console.print(f"\n[bold]Auditing hash {idx}/{len(hashes)}:[/bold] [dim]{target_hash[:32]}...[/dim] ({algo})")
        res = run_single_attack(
            target_hash=target_hash,
            algorithm=algo,
            strategy=strategy,
            strategy_params=params,
            use_prioritizer=use_prio,
        )
        results.append(res)

    total_time = time.time() - start_time
    cracked_count = sum(1 for r in results if r.found)
    total_count = len(results)

    console.print("\n" + "=" * 50)
    console.print("  [bold cyan]Batch Audit Summary[/bold cyan]")
    console.print("=" * 50)
    summary_table = Table(show_header=False, box=None)
    summary_table.add_column("Metric", style="bold")
    summary_table.add_column("Value")
    summary_table.add_row("Total Hashes Tested", str(total_count))
    summary_table.add_row("Recovered Passwords", f"[bold green]{cracked_count}[/bold green] ({cracked_count/total_count*100:.1f}%)")
    summary_table.add_row("Total Elapsed Time", f"{total_time:.2f}s")
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
    if "Pattern" in strat_name:
        strategy = PatternStrategy(
            base_prefix=params.get("base_prefix", ""),
            charset=params.get("charset", CHARSET_ALL_PRINTABLE),
            min_suffix_len=params.get("min_suffix_len", 1),
            max_suffix_len=params.get("max_suffix_len", 2),
        )
    elif "Mask" in strat_name:
        strategy = MaskStrategy(mask=params.get("mask", "?u?l?l?d?d"))
    elif "Hybrid" in strat_name:
        strategy = HybridStrategy(
            base_words=params.get("base_words", "admin"),
            suffix_mask=params.get("suffix_mask", "?d?d?d?d"),
        )
    elif "Rules" in strat_name or "mutat" in strat_name.lower():
        strategy = RulesStrategy(base_words=params.get("base_words"))
    else:
        strategy = BruteForceStrategy(
            charset=params.get("charset", CHARSET_LOWER_NUM),
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
    """Run an automated demo showcasing hash detection, pattern streaming, and rule attacks."""
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

    console.print("\n[bold cyan]2. In-Memory Pattern Streaming on SHA-1 (Prefix 'bante' + 94-char ASCII):[/bold cyan]")
    strat = PatternStrategy(base_prefix="bante", charset=CHARSET_ALL_PRINTABLE, min_suffix_len=1, max_suffix_len=1)
    manager = ExecutionManager()
    res = manager.run("fd1fa8af619ee320f1fab31824616394cc62716a", "sha1", strat.candidates(), strategy_name=strat.name)
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
    parser.add_argument("-m", "--mode", choices=["pattern", "rules", "brute", "mask", "hybrid"], default="pattern", help="Attack mode")
    parser.add_argument("-p", "--prefix", default="", help="Base prefix for pattern strategy (e.g. 'bante')")
    parser.add_argument("--min-suffix", type=int, default=1, help="Min suffix length for pattern strategy")
    parser.add_argument("--max-suffix", type=int, default=2, help="Max suffix length for pattern strategy")
    parser.add_argument("--base-words", default="", help="Base word(s) for rules or hybrid attack")
    parser.add_argument("--mask", default="?u?l?l?d?d", help="Mask for mask/hybrid attack")
    parser.add_argument("--charset", default=CHARSET_ALL_PRINTABLE, help="Charset for pattern/brute-force")
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
        mode = args.mode or "pattern"

        if mode == "pattern":
            strategy = PatternStrategy(
                base_prefix=args.prefix,
                charset=args.charset,
                min_suffix_len=args.min_suffix,
                max_suffix_len=args.max_suffix,
            )
            params = {
                "base_prefix": args.prefix,
                "charset": args.charset,
                "min_suffix_len": args.min_suffix,
                "max_suffix_len": args.max_suffix,
            }
        elif mode == "brute":
            strategy = BruteForceStrategy(charset=args.charset, min_length=1, max_length=args.max_length)
            params = {"charset": args.charset, "min_length": 1, "max_length": args.max_length}
        elif mode == "mask":
            strategy = MaskStrategy(mask=args.mask)
            params = {"mask": args.mask}
        elif mode == "hybrid":
            strategy = HybridStrategy(base_words=args.base_words or "admin", suffix_mask=args.mask)
            params = {"base_words": args.base_words or "admin", "suffix_mask": args.mask}
        else:  # rules
            strategy = RulesStrategy(base_words=args.base_words if args.base_words else None)
            params = {"base_words": args.base_words}

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
