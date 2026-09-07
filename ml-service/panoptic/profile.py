"""Behavioural baseline.

A :class:`Profile` is a set of frequency tables learned from historical events:
how often each executable runs, per host, per user, etc. At scoring time it
answers "how rare is this combination?" on a 0 (routine) .. 1 (never seen)
scale, using a smoothed self-information estimate:

    p        = (count + alpha) / (total + alpha * cardinality)
    surprise = -log(p)
    rarity   = min(1, surprise / surprise_at_unseen)

This is deliberately simple and fully explainable -- no model, just counting.
The profile is built alongside the IsolationForest model (``train.py``) and
saved to ``artifacts/profile.json`` so scoring and training agree.
"""

from __future__ import annotations

import json
import math
from collections import Counter
from pathlib import Path

from .context import EventContext

ALPHA = 0.5

# kind -> how to derive the key from an EventContext
_KEY_FUNCS = {
    "host_exe": lambda c: _pair(c.host, c.exe or c.comm),
    "user_exe": lambda c: _pair(c.auid_name or c.auid, c.exe or c.comm),
    "exe": lambda c: _scalar(c.exe or c.comm),
    "record_type": lambda c: _scalar(c.record_type),
    "user_host": lambda c: _pair(c.auid_name or c.auid, c.host),
    "comm_exe": lambda c: _pair(c.comm, c.exe),
}

KINDS = tuple(_KEY_FUNCS)


def _scalar(value) -> str | None:
    if value in (None, "", -1):
        return None
    return str(value)


def _pair(a, b) -> str | None:
    a, b = _scalar(a), _scalar(b)
    if a is None or b is None:
        return None
    return f"{a}\x1f{b}"


class Profile:
    def __init__(self, tables: dict[str, Counter] | None = None, totals: dict[str, int] | None = None):
        self.tables: dict[str, Counter] = {k: Counter(tables.get(k, {})) if tables else Counter() for k in KINDS}
        self.totals: dict[str, int] = totals or {k: sum(self.tables[k].values()) for k in KINDS}
        self.event_count = totals.get("__events__", self.totals.get("record_type", 0)) if totals else 0

    # ---- build ----------------------------------------------------------------

    def observe(self, ctx: EventContext) -> None:
        self.event_count += 1
        for kind, key_fn in _KEY_FUNCS.items():
            key = key_fn(ctx)
            if key is None:
                continue
            self.tables[kind][key] += 1
            self.totals[kind] = self.totals.get(kind, 0) + 1

    @classmethod
    def from_events(cls, contexts) -> "Profile":
        profile = cls()
        for ctx in contexts:
            profile.observe(ctx)
        return profile

    # ---- query --------------------------------------------------------------

    def frequency(self, kind: str, key) -> int:
        table = self.tables.get(kind)
        if table is None:
            return 0
        if kind in ("host_exe", "user_exe", "user_host", "comm_exe"):
            resolved = _pair(*key) if isinstance(key, tuple) else key
        else:
            resolved = _scalar(key) if not isinstance(key, str) else key
        return int(table.get(resolved, 0)) if resolved else 0

    def rarity(self, kind: str, key) -> float:
        table = self.tables.get(kind)
        if not table:
            return 0.5  # no baseline for this dimension -> neutral
        if kind in ("host_exe", "user_exe", "user_host", "comm_exe"):
            resolved = _pair(*key) if isinstance(key, tuple) else key
        else:
            resolved = _scalar(key) if not isinstance(key, str) else key
        if resolved is None:
            return 0.5

        total = self.totals.get(kind, sum(table.values()))
        cardinality = max(len(table), 1)
        count = table.get(resolved, 0)

        p = (count + ALPHA) / (total + ALPHA * (cardinality + 1))
        surprise = -math.log(p)
        p_unseen = ALPHA / (total + ALPHA * (cardinality + 1))
        ceiling = -math.log(p_unseen)
        if ceiling <= 0:
            return 0.0
        return max(0.0, min(1.0, surprise / ceiling))

    # ---- persistence ------------------------------------------------------

    def to_dict(self) -> dict:
        # Cap each table so the artifact stays small; the long tail of
        # once-seen keys all resolve to ~max rarity anyway.
        out_tables = {}
        for kind, table in self.tables.items():
            out_tables[kind] = dict(table.most_common(5000))
        return {
            "version": 1,
            "event_count": self.event_count,
            "totals": self.totals,
            "tables": out_tables,
        }

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict()))

    @classmethod
    def load(cls, path: str | Path) -> "Profile":
        data = json.loads(Path(path).read_text())
        totals = dict(data.get("totals", {}))
        totals["__events__"] = data.get("event_count", 0)
        return cls(tables=data.get("tables", {}), totals=totals)

    @classmethod
    def empty(cls) -> "Profile":
        return cls()
