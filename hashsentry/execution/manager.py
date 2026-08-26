"""
Execution Manager - HashSentry (Phases 3 & 5)
==============================================
Manages candidate dispatch, single/multiprocess execution,
real-time progress reporting, and graceful session checkpointing.
"""

from dataclasses import dataclass
import itertools
import multiprocessing as mp
import os
import signal
import sys
import time
from typing import Any, Callable, Dict, Generator, Iterable, List, Optional, Tuple

from hashsentry.core.handlers import BaseHashHandler, get_handler
from hashsentry.execution.checkpoint import delete_checkpoint, save_checkpoint


@dataclass
class CrackResult:
    found: bool
    password: Optional[str]
    attempts: int
    elapsed_seconds: float
    strategy_name: str
    algorithm: str
    target_hash: str
    interrupted: bool = False
    run_id: Optional[str] = None
    checkpoint_file: Optional[str] = None

    @property
    def speed(self) -> float:
        if self.elapsed_seconds > 0:
            return self.attempts / self.elapsed_seconds
        return float(self.attempts)


def _worker_check_chunk(
    args: Tuple[List[str], str, str]
) -> Tuple[Optional[str], int, Optional[str]]:
    """
    Multiprocessing worker function.
    args: (chunk_of_candidates, target_hash, algo_name)
    Returns: (found_password_or_None, attempts_count, last_tested_candidate)
    """
    candidates, target_hash, algo_name = args
    handler = get_handler(algo_name)
    count = 0
    last_cand = None
    for cand in candidates:
        count += 1
        last_cand = cand
        if handler.verify(cand, target_hash):
            return cand, count, last_cand
    return None, count, last_cand


class ExecutionManager:
    """
    Orchestrates cracking execution over candidates using configured handlers.
    Supports single-threaded execution and multi-core multiprocessing.
    """

    def __init__(
        self,
        num_workers: Optional[int] = None,
        chunk_size: int = 1000,
        progress_callback: Optional[Callable[[int, float, float, Optional[str], Optional[int]], None]] = None,
        progress_interval: float = 0.25,
    ):
        self.num_workers = num_workers if num_workers is not None else max(1, os.cpu_count() or 1)
        self.chunk_size = chunk_size
        self.progress_callback = progress_callback
        self.progress_interval = progress_interval
        self._interrupted = False

    def _chunk_generator(
        self, stream: Iterable[str], chunk_size: int
    ) -> Generator[List[str], None, None]:
        """Yield chunks of size chunk_size from an iterable."""
        it = iter(stream)
        while True:
            chunk = list(itertools.islice(it, chunk_size))
            if not chunk:
                break
            yield chunk

    def run(
        self,
        target_hash: str,
        algorithm: str,
        candidates_generator: Iterable[str],
        strategy_name: str = "Unknown",
        strategy_params: Optional[Dict[str, Any]] = None,
        estimated_total: Optional[int] = None,
        run_id: Optional[str] = None,
        skip_attempts: int = 0,
        initial_elapsed: float = 0.0,
        use_multiprocessing: bool = True,
    ) -> CrackResult:
        """
        Execute candidate testing against target_hash.
        """
        if run_id is None:
            safe_hash = target_hash[:8] if len(target_hash) >= 8 else "target"
            run_id = f"run_{strategy_name.lower().replace(' ', '_')}_{safe_hash}_{int(time.time())}"

        if strategy_params is None:
            strategy_params = {}

        handler = get_handler(algorithm)
        attempts = skip_attempts
        start_time = time.time()
        last_progress_time = 0.0
        last_candidate: Optional[str] = None
        found_password: Optional[str] = None
        self._interrupted = False

        # Generator with skipping if resuming
        candidates_iter = iter(candidates_generator)
        if skip_attempts > 0:
            for _ in range(skip_attempts):
                try:
                    next(candidates_iter)
                except StopIteration:
                    break

        # Adjust chunk size: for slow hashes (bcrypt/argon2), smaller chunk sizes (e.g. 10-50) give smoother responsiveness
        active_chunk_size = self.chunk_size
        if handler.is_slow:
            active_chunk_size = max(1, min(50, self.chunk_size // 20))

        # Single-process path if 1 worker or slow single hash or explicitly disabled
        if not use_multiprocessing or self.num_workers <= 1:
            try:
                for candidate in candidates_iter:
                    attempts += 1
                    last_candidate = candidate
                    now = time.time()
                    elapsed = initial_elapsed + (now - start_time)

                    if handler.verify(candidate, target_hash):
                        found_password = candidate
                        break

                    if (
                        self.progress_callback
                        and (now - last_progress_time) >= self.progress_interval
                    ):
                        speed = attempts / elapsed if elapsed > 0 else float(attempts)
                        self.progress_callback(
                            attempts, elapsed, speed, last_candidate, estimated_total
                        )
                        last_progress_time = now

            except KeyboardInterrupt:
                self._interrupted = True
        else:
            # Multiprocessing pool execution
            pool = None
            try:
                pool = mp.Pool(processes=self.num_workers)
                chunks = self._chunk_generator(candidates_iter, active_chunk_size)

                for chunk in chunks:
                    if self._interrupted:
                        break

                    # Map chunk across workers
                    # Split chunk into subchunks for each worker
                    subchunk_size = max(1, len(chunk) // self.num_workers)
                    worker_tasks = []
                    for i in range(0, len(chunk), subchunk_size):
                        sub = chunk[i : i + subchunk_size]
                        worker_tasks.append((sub, target_hash, algorithm))

                    # Execute with pool map
                    results = pool.map(_worker_check_chunk, worker_tasks)

                    for match, chunk_attempts, last_sub_cand in results:
                        attempts += chunk_attempts
                        if last_sub_cand:
                            last_candidate = last_sub_cand
                        if match is not None and found_password is None:
                            found_password = match

                    now = time.time()
                    elapsed = initial_elapsed + (now - start_time)

                    if (
                        self.progress_callback
                        and (now - last_progress_time) >= self.progress_interval
                    ):
                        speed = attempts / elapsed if elapsed > 0 else float(attempts)
                        self.progress_callback(
                            attempts, elapsed, speed, last_candidate, estimated_total
                        )
                        last_progress_time = now

                    if found_password is not None:
                        break

            except KeyboardInterrupt:
                self._interrupted = True
            finally:
                if pool:
                    pool.terminate()
                    pool.join()

        total_elapsed = initial_elapsed + (time.time() - start_time)
        final_speed = attempts / total_elapsed if total_elapsed > 0 else float(attempts)

        # Final progress update
        if self.progress_callback:
            self.progress_callback(
                attempts, total_elapsed, final_speed, last_candidate, estimated_total
            )

        checkpoint_path = None
        if self._interrupted:
            # Save checkpoint
            checkpoint_path = save_checkpoint(
                run_id=run_id,
                target_hash=target_hash,
                algorithm=algorithm,
                strategy_name=strategy_name,
                strategy_params=strategy_params,
                attempts=attempts,
                elapsed_seconds=total_elapsed,
                last_candidate=last_candidate,
            )
        elif found_password is not None:
            # Clean up checkpoint on success
            delete_checkpoint(run_id)

        return CrackResult(
            found=(found_password is not None),
            password=found_password,
            attempts=attempts,
            elapsed_seconds=total_elapsed,
            strategy_name=strategy_name,
            algorithm=algorithm,
            target_hash=target_hash,
            interrupted=self._interrupted,
            run_id=run_id,
            checkpoint_file=checkpoint_path,
        )
