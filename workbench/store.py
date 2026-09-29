"""SQLite claim ledger. Every finding is a claim with provenance.

Tiers:
  VERIFIED — directly observed from a named public source
  INFERRED  — derived by linking two or more verified claims
  GUESSED   — heuristic pattern match, labeled as such
  DEGRADED  — a source was unreachable; the gap itself is recorded
"""
from __future__ import annotations

import json
import os
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(
  id INTEGER PRIMARY KEY,
  target TEXT NOT NULL,
  started_at TEXT NOT NULL,
  status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS claims(
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL,
  tier TEXT NOT NULL,
  claim TEXT NOT NULL,
  source TEXT NOT NULL,
  source_url TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  analyst_status TEXT NOT NULL DEFAULT 'unreviewed',
  detail TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS links(
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL,
  entity_type TEXT NOT NULL,
  entity_value TEXT NOT NULL,
  claim_ids TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS assessments(
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  markdown TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS attestations(
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL,
  text TEXT NOT NULL,
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS snapshots(
  id INTEGER PRIMARY KEY,
  target TEXT NOT NULL,
  run_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  snapshot TEXT NOT NULL);
"""


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class Store:
    def __init__(self, path: str):
        self.cx = sqlite3.connect(path)
        self.cx.row_factory = sqlite3.Row
        self.cx.executescript(SCHEMA)
        self.cx.commit()

    def close(self):
        self.cx.close()

    # -- runs ------------------------------------------------------------
    def new_run(self, target: str) -> int:
        cur = self.cx.execute(
            "INSERT INTO runs(target, started_at, status) VALUES (?,?,?)",
            (target, now(), "collecting"),
        )
        self.cx.commit()
        return cur.lastrowid

    def finish_run(self, run_id: int, status: str = "collected"):
        self.cx.execute("UPDATE runs SET status=? WHERE id=?", (status, run_id))
        self.cx.commit()

    def get_run(self, run_id: int):
        return self.cx.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()

    def latest_run(self, target: str):
        return self.cx.execute(
            "SELECT * FROM runs WHERE target=? ORDER BY id DESC LIMIT 1", (target,)
        ).fetchone()

    # -- claims ----------------------------------------------------------
    def add_claim(self, run_id, tier, claim, source, source_url, observed_at, detail="") -> int:
        if isinstance(detail, (dict, list)):
            detail = json.dumps(detail)
        cur = self.cx.execute(
            """INSERT INTO claims(run_id, tier, claim, source, source_url,
                                  observed_at, detail)
               VALUES (?,?,?,?,?,?,?)""",
            (run_id, tier, claim, source, source_url, observed_at, detail),
        )
        self.cx.commit()
        return cur.lastrowid

    def get_claims(self, run_id, tier=None):
        q = "SELECT * FROM claims WHERE run_id=? ORDER BY id"
        args: tuple = (run_id,)
        if tier:
            q = "SELECT * FROM claims WHERE run_id=? AND tier=? ORDER BY id"
            args = (run_id, tier)
        return self.cx.execute(q, args).fetchall()

    def set_claim_status(self, claim_id: int, status: str):
        assert status in ("approved", "rejected", "unreviewed")
        self.cx.execute("UPDATE claims SET analyst_status=? WHERE id=?", (status, claim_id))
        self.cx.commit()

    # -- links -----------------------------------------------------------
    def add_link(self, run_id, entity_type, entity_value, claim_ids) -> int:
        cur = self.cx.execute(
            "INSERT INTO links(run_id, entity_type, entity_value, claim_ids) VALUES (?,?,?,?)",
            (run_id, entity_type, entity_value, json.dumps(sorted(set(claim_ids)))),
        )
        self.cx.commit()
        return cur.lastrowid

    def get_links(self, run_id):
        return self.cx.execute("SELECT * FROM links WHERE run_id=? ORDER BY id", (run_id,)).fetchall()

    # -- snapshots (Layer B: temporal sentinel) ---------------------------
    def save_snapshot(self, target: str, run_id: int, snapshot: dict) -> int:
        cur = self.cx.execute(
            "INSERT INTO snapshots(target, run_id, created_at, snapshot) VALUES (?,?,?,?)",
            (target, run_id, now(), json.dumps(snapshot, sort_keys=True)),
        )
        self.cx.commit()
        return cur.lastrowid

    def latest_snapshot_before(self, target: str, run_id: int):
        """Most recent snapshot for target from an earlier run, or None."""
        return self.cx.execute(
            "SELECT * FROM snapshots WHERE target=? AND run_id < ? ORDER BY run_id DESC LIMIT 1",
            (target, run_id)).fetchone()

    # -- assessments / attestations --------------------------------------
    def add_assessment(self, run_id, markdown) -> int:
        cur = self.cx.execute(
            "INSERT INTO assessments(run_id, created_at, markdown) VALUES (?,?,?)",
            (run_id, now(), markdown),
        )
        self.cx.commit()
        return cur.lastrowid

    def add_attestation(self, run_id, text):
        self.cx.execute(
            "INSERT INTO attestations(run_id, text, created_at) VALUES (?,?,?)",
            (run_id, text, now()),
        )
        self.cx.commit()
