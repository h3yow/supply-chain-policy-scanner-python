"""扫描结果缓存：内容哈希 + 策略版本为键，并发同键只计算一次。"""
from __future__ import annotations

import logging
import threading
from collections.abc import Callable

from .models import ScanReport

logger = logging.getLogger("scanner.cache")


class ScanCache:
    """单飞（single-flight）缓存：同键并发请求共享一次计算结果。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[tuple[str, int], ScanReport] = {}
        self._inflight: dict[tuple[str, int], threading.Event] = {}

    def get_or_compute(self, key: tuple[str, int], compute: Callable[[], ScanReport]) -> ScanReport:
        """命中直接返回；未命中时同键仅一个线程执行 compute，其余等待其结果。"""
        with self._lock:
            cached = self._entries.get(key)
            if cached is not None:
                logger.info("cache hit: content_hash=%s policy_version=%d", key[0], key[1])
                return cached
            event = self._inflight.get(key)
            if event is None:
                event = threading.Event()
                self._inflight[key] = event
                owner = True
            else:
                owner = False
        if owner:
            try:
                report = compute()
            finally:
                with self._lock:
                    self._inflight.pop(key, None)
                    event.set()
            with self._lock:
                # 计算期间策略可能已变更导致键被失效，仅在键仍有效时写入
                self._entries.setdefault(key, report)
                return self._entries[key]
        event.wait()
        with self._lock:
            cached = self._entries.get(key)
        if cached is not None:
            return cached
        # 极少见：owner 计算期间键被失效，退化为自行计算
        return compute()

    def invalidate_policy(self, policy_version: int) -> int:
        """使某策略版本的所有缓存失效，返回清除条数。"""
        with self._lock:
            keys = [k for k in self._entries if k[1] == policy_version]
            for k in keys:
                del self._entries[k]
        if keys:
            logger.info("cache invalidated: policy_version=%d entries=%d", policy_version, len(keys))
        return len(keys)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def invalidate_except(self, active_policy_version: int) -> int:
        """清除所有不属于当前生效策略版本的条目，返回清除条数。"""
        with self._lock:
            keys = [k for k in self._entries if k[1] != active_policy_version]
            for k in keys:
                del self._entries[k]
        if keys:
            logger.info("cache invalidated: active_policy_version=%d removed=%d", active_policy_version, len(keys))
        return len(keys)
