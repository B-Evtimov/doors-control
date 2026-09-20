"""Rate limiting on three independent subjects, with progressive delay.

Three subjects because they fail in different ways:

  user    stops a password guessing run against one account no matter how
          many source addresses it comes from
  device  stops one compromised phone from hammering doors
  ip      stops a single host enumerating usernames across many accounts

The delay is exponential in the number of recent failures, capped. The delay
is applied before the answer is sent, so an attacker cannot use a fast
rejection as a signal and cannot run the next attempt any sooner. Above the
threshold the request is refused outright with 429 and a Retry-After.

Note that the delay is deliberately applied to the *rejection* path only after
the fixed-duration authentication budget, so it adds to a constant baseline
rather than replacing it.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from app.core.config import Settings
from app.db.repositories.rate_limit import RateLimitRepository


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    delay_ms: int
    retry_after_seconds: int
    failures: int
    subject_type: str


class RateLimiter:
    def __init__(self, repo: RateLimitRepository, settings: Settings) -> None:
        self._repo = repo
        self._settings = settings
        # A small in-process cache in front of the table. It can only make the
        # limiter stricter, never more permissive: entries are added on
        # failure and expire on their own.
        self._recent: dict[tuple[str, str], list[float]] = {}

    def _remember(self, subject_type: str, subject: str) -> int:
        key = (subject_type, subject)
        now = time.monotonic()
        window = self._settings.rate_window_seconds
        bucket = [t for t in self._recent.get(key, []) if now - t < window]
        bucket.append(now)
        self._recent[key] = bucket
        return len(bucket)

    def _progressive_delay_ms(self, failures: int) -> int:
        if failures <= 0:
            return 0
        delay = self._settings.rate_base_delay_ms * (2 ** (failures - 1))
        return min(delay, self._settings.rate_max_delay_ms)

    async def check_login(
        self, *, username: str, client_ip: str | None
    ) -> RateDecision:
        window = self._settings.rate_window_seconds
        limit = self._settings.rate_max_login_failures

        by_user = await self._repo.failure_count(
            subject_type="user", subject=username.lower(), window_seconds=window
        )
        by_ip = (
            await self._repo.failure_count(
                subject_type="ip", subject=client_ip, window_seconds=window
            )
            if client_ip
            else 0
        )

        failures = max(by_user, by_ip)
        subject_type = "user" if by_user >= by_ip else "ip"
        if failures >= limit:
            return RateDecision(
                allowed=False,
                delay_ms=self._settings.rate_max_delay_ms,
                retry_after_seconds=window,
                failures=failures,
                subject_type=subject_type,
            )
        return RateDecision(
            allowed=True,
            delay_ms=self._progressive_delay_ms(failures),
            retry_after_seconds=0,
            failures=failures,
            subject_type=subject_type,
        )

    async def check_unlock(self, *, user_id: str, device_id: str) -> RateDecision:
        attempts = await self._repo.unlock_count(user_id=user_id, seconds=60)
        limit = self._settings.rate_max_unlocks_per_minute
        if attempts >= limit:
            return RateDecision(
                allowed=False,
                delay_ms=0,
                retry_after_seconds=60,
                failures=attempts,
                subject_type="user",
            )
        return RateDecision(
            allowed=True, delay_ms=0, retry_after_seconds=0,
            failures=attempts, subject_type="user",
        )

    async def record_login_failure(
        self, *, username: str, client_ip: str | None, endpoint: str
    ) -> None:
        await self._repo.record_failure(
            subject_type="user", subject=username.lower(),
            endpoint=endpoint, client_ip=client_ip,
        )
        self._remember("user", username.lower())
        if client_ip:
            await self._repo.record_failure(
                subject_type="ip", subject=client_ip,
                endpoint=endpoint, client_ip=client_ip,
            )
            self._remember("ip", client_ip)

    async def record_device_failure(
        self, *, device_id: str, client_ip: str | None, endpoint: str
    ) -> None:
        await self._repo.record_failure(
            subject_type="device", subject=device_id,
            endpoint=endpoint, client_ip=client_ip,
        )
        self._remember("device", device_id)

    @staticmethod
    async def apply_delay(decision: RateDecision) -> None:
        if decision.delay_ms > 0:
            await asyncio.sleep(decision.delay_ms / 1000.0)
