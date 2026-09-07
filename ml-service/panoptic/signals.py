"""Batch-local rolling signals.

Some detections need short-horizon context that a single event can't carry:
"how many auth failures has this account had in the last few minutes",
"how many distinct ports has this host just connected to". Computing that with
a per-event Elasticsearch query would be 1000 extra queries per cycle.

Instead we exploit the fact that the scoring loop reads events in ascending
timestamp order: a :class:`RollingSignals` accumulator walks the batch once and
maintains time-windowed counters keyed by (host, account) / host. The tradeoff
is that the window resets at batch boundaries -- acceptable, and documented.
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta

from .context import EventContext

AUTH_WINDOW = timedelta(minutes=10)
PORT_WINDOW = timedelta(minutes=5)


class RollingSignals:
    def __init__(self, auth_window: timedelta = AUTH_WINDOW, port_window: timedelta = PORT_WINDOW):
        self.auth_window = auth_window
        self.port_window = port_window
        self._auth_fail: dict[tuple, deque] = defaultdict(deque)
        self._ports: dict[str, deque] = defaultdict(deque)

    @staticmethod
    def _account_key(ctx: EventContext) -> tuple:
        account = (
            ctx.acct
            or ctx.auid_name
            or (str(ctx.auid) if ctx.auid >= 0 else None)
            or ctx.user_name
            or (str(ctx.uid) if ctx.uid >= 0 else None)
            or "unknown"
        )
        return (ctx.host, account)

    def update(self, ctx: EventContext) -> dict:
        """Feed one event (in timestamp order) and return its signal dict."""

        now = ctx.timestamp
        signals = {"recent_auth_failures": 0, "recent_distinct_ports": 0}
        if now is None:
            return signals

        # --- auth failures ---
        key = self._account_key(ctx)
        bucket = self._auth_fail[key]
        if ctx.is_auth_failure:
            bucket.append(now)
        while bucket and now - bucket[0] > self.auth_window:
            bucket.popleft()
        signals["recent_auth_failures"] = len(bucket)

        # --- distinct destination ports per host ---
        if ctx.dest_port and ctx.dest_port > 0 and ctx.host:
            pbucket = self._ports[ctx.host]
            pbucket.append((now, ctx.dest_port))
            while pbucket and now - pbucket[0][0] > self.port_window:
                pbucket.popleft()
            signals["recent_distinct_ports"] = len({p for _, p in pbucket})
        elif ctx.host and ctx.host in self._ports:
            pbucket = self._ports[ctx.host]
            while pbucket and now - pbucket[0][0] > self.port_window:
                pbucket.popleft()
            signals["recent_distinct_ports"] = len({p for _, p in pbucket})

        ctx.recent_auth_failures = signals["recent_auth_failures"]
        ctx.recent_distinct_ports = signals["recent_distinct_ports"]
        return signals
