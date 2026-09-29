"""Concurrent scan cache.

Guarantees:

* identical cache keys are computed exactly once under concurrency:
  in-flight requests share a single :class:`~concurrent.futures.Future`;
* ``invalidate_all`` (called on policy publish/rollback) advances an epoch so
  that (a) finished results are dropped and (b) a computation that was
  already in flight at invalidation time can neither populate the cache nor
  satisfy requests issued afterwards - they start a fresh computation;
* the store lock is never held while user computation runs.
"""
from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor

from scanner.models import ScanResult


class ScanCache:
    def __init__(self, max_workers: int = 8) -> None:
        self._lock = threading.Lock()
        self._results: dict[str, ScanResult] = {}
        self._inflight: dict[str, tuple[int, Future[ScanResult]]] = {}
        self._epoch = 0
        self._executor = ThreadPoolExecutor(max_workers=max_workers,
                                            thread_name_prefix="scan")

    def get_or_compute(self, key: str, compute: Callable[[], ScanResult]) -> ScanResult:
        while True:
            with self._lock:
                hit = self._results.get(key)
                if hit is not None:
                    return hit
                entry = self._inflight.get(key)
                if entry is not None:
                    epoch, future = entry
                else:
                    epoch, future = self._epoch, Future()
                    self._inflight[key] = (epoch, future)
                    own = True
                if entry is not None:
                    own = False

            if not own:
                result = future.result()  # share the single computation
                with self._lock:
                    if self._inflight.get(key, (epoch,))[0] != epoch:
                        continue  # invalidated while we waited: recompute
                    if self._results.get(key) is not None:
                        return self._results[key]
                return result

            # owner: run the (single) computation off the caller thread
            def worker() -> None:
                try:
                    future.set_result(compute())
                except BaseException as exc:  # propagate to every waiter
                    if not future.done():
                        future.set_exception(exc)

            self._executor.submit(worker)
            result = future.result()
            with self._lock:
                self._inflight.pop(key, None)
                if self._epoch == epoch:
                    self._results[key] = result
                # else: a publish/rollback happened mid-computation; the stale
                # result is returned to this caller but never cached.
            return result

    def invalidate_all(self) -> None:
        with self._lock:
            self._epoch += 1
            self._results.clear()
            self._inflight.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._results)
