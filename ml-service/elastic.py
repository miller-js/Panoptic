"""All Elasticsearch I/O for the ML service.

Nothing else in the service imports ``elasticsearch`` directly. The detector
pipeline works on plain dicts; this module is the only thing that knows about
indices, cursors, and the bulk API.
"""

from __future__ import annotations

import logging
from typing import Iterable

from elasticsearch import Elasticsearch, NotFoundError
from elasticsearch.helpers import bulk

import config as cfg

log = logging.getLogger("panoptic.elastic")

CURSOR_DOC_ID = "scan-cursor"


class ElasticClient:
    def __init__(self, conf: cfg.ElasticConfig | None = None):
        conf = conf or cfg.ElasticConfig()
        self.es = Elasticsearch(
            conf.addr,
            basic_auth=(conf.user, conf.password),
            request_timeout=conf.request_timeout,
        )
        self.source_index = cfg.SOURCE_INDEX
        self.alerts_index = cfg.ALERTS_INDEX
        self.state_index = cfg.STATE_INDEX

    # ---- health / setup ------------------------------------------------

    def ping(self) -> bool:
        return bool(self.es.ping())

    def info(self) -> dict:
        return self.es.info().body

    def ensure_index(self, name: str, body: dict) -> bool:
        """Create ``name`` with ``body`` if absent. Returns True if created."""

        if self.es.indices.exists(index=name):
            return False
        self.es.indices.create(index=name, body=body)
        log.info("created index %s", name)
        return True

    def ensure_state_index(self) -> None:
        self.ensure_index(
            self.state_index,
            {"mappings": {"properties": {
                "last_timestamp": {"type": "date"},
                "last_seq_no": {"type": "long"},
                "updated_at": {"type": "date"},
            }}},
        )

    # ---- scan cursor -------------------------------------------------

    def read_cursor(self) -> dict | None:
        try:
            doc = self.es.get(index=self.state_index, id=CURSOR_DOC_ID)
            return doc["_source"]
        except NotFoundError:
            return None

    def write_cursor(self, last_timestamp: str, last_seq_no: int | None = None) -> None:
        from datetime import datetime, timezone

        self.es.index(
            index=self.state_index,
            id=CURSOR_DOC_ID,
            document={
                "last_timestamp": last_timestamp,
                "last_seq_no": last_seq_no,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            },
        )

    # ---- reading source logs -------------------------------------

    def fetch_unprocessed(self, size: int) -> list[dict]:
        """Next ``size`` source docs strictly after the cursor, timestamp asc.

        Relies on Elasticsearch's ~1s refresh making newly-indexed docs visible
        between cycles -- fine for the real 300s loop.
        """

        cursor = self.read_cursor()
        if cursor and cursor.get("last_timestamp"):
            query = {"range": {"@timestamp": {"gt": cursor["last_timestamp"]}}}
        else:
            query = {"match_all": {}}

        # A plain search is capped at index.max_result_window (10k). Larger
        # batches would need search_after; not worth it -- 10k source docs is
        # already a big cycle.
        size = min(size, 10000)
        resp = self.es.search(
            index=self.source_index,
            size=size,
            query=query,
            sort=[{"@timestamp": {"order": "asc"}}, {"_doc": {"order": "asc"}}],
        )
        return [hit["_source"] for hit in resp["hits"]["hits"]]

    def random_sample(self, size: int, seed: int) -> list[dict]:
        """Uniform-ish random sample of source docs for model training."""

        out: list[dict] = []
        page = min(size, 5000)
        # function_score + random_score gives a stable pseudo-random ordering
        query = {
            "function_score": {
                "query": {"match_all": {}},
                "random_score": {"seed": seed, "field": "_seq_no"},
                "boost_mode": "replace",
            }
        }
        resp = self.es.search(index=self.source_index, size=page, query=query)
        for hit in resp["hits"]["hits"]:
            out.append(hit["_source"])
        return out[:size]

    def scroll_sample(self, size: int, seed: int) -> list[dict]:
        """Larger random sample via search_after over a random_score sort."""

        out: list[dict] = []
        query = {
            "function_score": {
                "query": {"match_all": {}},
                "random_score": {"seed": seed, "field": "_seq_no"},
                "boost_mode": "replace",
            }
        }
        search_after = None
        page = 2000
        while len(out) < size:
            body = {
                "size": min(page, size - len(out)),
                "query": query,
                "sort": [{"_score": {"order": "desc"}}, {"_doc": "asc"}],
                "track_total_hits": False,
            }
            if search_after:
                body["search_after"] = search_after
            resp = self.es.search(index=self.source_index, body=body)
            hits = resp["hits"]["hits"]
            if not hits:
                break
            out.extend(h["_source"] for h in hits)
            search_after = hits[-1]["sort"]
        return out[:size]

    def count(self, index: str) -> int:
        return int(self.es.count(index=index)["count"])

    def search(self, index: str, body: dict) -> dict:
        return self.es.search(index=index, body=body).body

    # ---- writing alerts ------------------------------------------

    def bulk_index_alerts(self, id_doc_pairs: Iterable[tuple[str, dict]]) -> tuple[int, int]:
        actions = (
            {"_op_type": "index", "_index": self.alerts_index, "_id": _id, "_source": doc}
            for _id, doc in id_doc_pairs
        )
        success, errors = bulk(self.es, actions, stats_only=False, raise_on_error=False)
        error_count = len(errors) if isinstance(errors, list) else int(errors)
        return success, error_count

    def refresh(self, index: str) -> None:
        try:
            self.es.indices.refresh(index=index)
        except Exception:  # noqa: BLE001 -- refresh is best-effort
            pass
