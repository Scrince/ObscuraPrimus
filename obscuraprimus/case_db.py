from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path


SCHEMA = """
create table if not exists evidence (
  id integer primary key autoincrement,
  path text not null,
  sha256 text not null,
  size integer not null,
  tags text not null default '',
  notes text not null default '',
  added real not null
);
create table if not exists audit (
  id integer primary key autoincrement,
  timestamp real not null,
  message text not null
);
create table if not exists files (
  id integer primary key autoincrement,
  path text not null unique,
  sha256 text not null,
  size integer not null,
  magic_type text not null default '',
  risk_score integer not null default 0,
  parser_confidence text not null default 'heuristic',
  added real not null
);
create table if not exists findings (
  id integer primary key autoincrement,
  file_id integer,
  title text not null,
  detail text not null default '',
  severity text not null default 'medium',
  status text not null default 'open',
  owner text not null default '',
  false_positive integer not null default 0,
  include_in_report integer not null default 1,
  created real not null,
  updated real not null,
  foreign key(file_id) references files(id)
);
create table if not exists iocs (
  id integer primary key autoincrement,
  file_id integer,
  kind text not null,
  value text not null,
  foreign key(file_id) references files(id)
);
create table if not exists timeline_events (
  id integer primary key autoincrement,
  file_id integer,
  timestamp real not null,
  kind text not null,
  detail text not null default '',
  foreign key(file_id) references files(id)
);
create table if not exists notes (
  id integer primary key autoincrement,
  file_id integer,
  note text not null,
  author text not null default '',
  created real not null,
  foreign key(file_id) references files(id)
);
create table if not exists tags (
  id integer primary key autoincrement,
  file_id integer,
  tag text not null,
  foreign key(file_id) references files(id)
);
create table if not exists reports (
  id integer primary key autoincrement,
  path text not null,
  sha256 text not null default '',
  signed integer not null default 0,
  created real not null
);
create table if not exists chain_of_custody (
  id integer primary key autoincrement,
  timestamp real not null,
  actor text not null default '',
  action text not null,
  detail text not null default ''
);
"""


def init_case_db(case_dir: str | Path) -> Path:
    root = Path(case_dir)
    root.mkdir(parents=True, exist_ok=True)
    db_path = root / "case.db"
    con = sqlite3.connect(db_path)
    try:
        con.executescript(SCHEMA)
        _ensure_fts(con)
        con.execute("insert into audit(timestamp, message) values (?, ?)", (time.time(), "case-db-opened"))
        con.commit()
    finally:
        con.close()
    return db_path


def add_evidence_record(case_dir: str | Path, path: str, sha256: str, size: int, tags: list[str], notes: str) -> None:
    db_path = init_case_db(case_dir)
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            "insert into evidence(path, sha256, size, tags, notes, added) values (?, ?, ?, ?, ?, ?)",
            (path, sha256, size, ",".join(tags), notes, time.time()),
        )
        con.execute("insert into audit(timestamp, message) values (?, ?)", (time.time(), f"evidence-added {path}"))
        file_id = upsert_file_record(con, path, sha256, size)
        for tag in tags:
            con.execute("insert into tags(file_id, tag) values (?, ?)", (file_id, tag))
        if notes:
            con.execute("insert into notes(file_id, note, created) values (?, ?, ?)", (file_id, notes, time.time()))
        con.execute(
            "insert into chain_of_custody(timestamp, action, detail) values (?, ?, ?)",
            (time.time(), "evidence-added", f"{path} sha256={sha256}"),
        )
        con.commit()
    finally:
        con.close()


def dashboard(case_dir: str | Path) -> dict:
    db_path = init_case_db(case_dir)
    con = sqlite3.connect(db_path)
    try:
        total = con.execute("select count(*) from files").fetchone()[0]
        duplicates = con.execute("select sha256, count(*) from evidence group by sha256 having count(*) > 1").fetchall()
        tags = con.execute("select tags from evidence").fetchall()
        open_findings = con.execute("select count(*) from findings where status != 'closed'").fetchone()[0]
        high = con.execute("select count(*) from files where risk_score >= 70").fetchone()[0]
    finally:
        con.close()
    tag_counts: dict[str, int] = {}
    for row in tags:
        for tag in row[0].split(","):
            if tag:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1
    return {"evidence_count": total, "duplicate_hashes": dict(duplicates), "tag_counts": tag_counts, "open_findings": open_findings, "high_risk_files": high}


def upsert_file_record(
    con: sqlite3.Connection,
    path: str,
    sha256: str,
    size: int,
    magic_type: str = "",
    risk_score: int = 0,
    parser_confidence: str = "heuristic",
) -> int:
    now = time.time()
    con.execute(
        """
        insert into files(path, sha256, size, magic_type, risk_score, parser_confidence, added)
        values (?, ?, ?, ?, ?, ?, ?)
        on conflict(path) do update set
          sha256=excluded.sha256,
          size=excluded.size,
          magic_type=excluded.magic_type,
          risk_score=excluded.risk_score,
          parser_confidence=excluded.parser_confidence
        """,
        (path, sha256, size, magic_type, risk_score, parser_confidence, now),
    )
    return int(con.execute("select id from files where path = ?", (path,)).fetchone()[0])


def store_analysis_results(case_dir: str | Path, results) -> None:
    db_path = init_case_db(case_dir)
    con = sqlite3.connect(db_path)
    try:
        for item in results:
            file_id = upsert_file_record(
                con,
                item.path,
                item.hashes.get("sha256", ""),
                item.size,
                item.magic_type,
                item.risk_score,
                parser_confidence(item),
            )
            con.execute("delete from iocs where file_id = ?", (file_id,))
            con.execute("delete from timeline_events where file_id = ?", (file_id,))
            for kind, values in item.iocs.items():
                for value in values:
                    con.execute("insert into iocs(file_id, kind, value) values (?, ?, ?)", (file_id, kind, value))
            for kind, timestamp in item.timestamps.items():
                con.execute(
                    "insert into timeline_events(file_id, timestamp, kind, detail) values (?, ?, ?, ?)",
                    (file_id, timestamp, kind, item.path),
                )
            if item.suspicious:
                for flag in item.suspicious:
                    add_finding(con, file_id, flag[:120], flag, severity_from_score(item.risk_score))
            _index_fts(con, file_id, item)
        con.execute("insert into audit(timestamp, message) values (?, ?)", (time.time(), f"analysis-stored {len(results)} files"))
        con.commit()
    finally:
        con.close()


def create_finding(case_dir: str | Path, file_path: str, title: str, detail: str = "", severity: str = "medium") -> int:
    db_path = init_case_db(case_dir)
    con = sqlite3.connect(db_path)
    try:
        row = con.execute("select id from files where path = ?", (file_path,)).fetchone()
        file_id = int(row[0]) if row else None
        finding_id = add_finding(con, file_id, title, detail, severity)
        con.commit()
        return finding_id
    finally:
        con.close()


def update_finding(case_dir: str | Path, finding_id: int, **fields) -> None:
    allowed = {"status", "severity", "owner", "false_positive", "include_in_report", "detail", "title"}
    updates = {key: value for key, value in fields.items() if key in allowed}
    if not updates:
        return
    updates["updated"] = time.time()
    db_path = init_case_db(case_dir)
    con = sqlite3.connect(db_path)
    try:
        clause = ", ".join(f"{key}=?" for key in updates)
        con.execute(f"update findings set {clause} where id = ?", (*updates.values(), finding_id))
        con.commit()
    finally:
        con.close()


def search_fts(case_dir: str | Path, query: str) -> list[dict]:
    db_path = init_case_db(case_dir)
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            """
            select files.*, case_fts.rank
            from case_fts join files on files.id = case_fts.rowid
            where case_fts match ?
            order by case_fts.rank
            limit 100
            """,
            (query,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        con.close()


def add_report_record(case_dir: str | Path, path: str | Path, sha256: str = "", signed: bool = False) -> None:
    db_path = init_case_db(case_dir)
    con = sqlite3.connect(db_path)
    try:
        con.execute("insert into reports(path, sha256, signed, created) values (?, ?, ?, ?)", (str(path), sha256, int(signed), time.time()))
        con.commit()
    finally:
        con.close()


def parser_confidence(analysis) -> str:
    if analysis.metadata.get("clamav") or analysis.metadata.get("yara_matches"):
        return "external-tool"
    if analysis.magic_type != "unknown" and not analysis.signature_mismatch:
        return "confirmed"
    return "heuristic"


def severity_from_score(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def add_finding(con: sqlite3.Connection, file_id: int | None, title: str, detail: str, severity: str = "medium") -> int:
    now = time.time()
    cur = con.execute(
        """
        insert into findings(file_id, title, detail, severity, created, updated)
        values (?, ?, ?, ?, ?, ?)
        """,
        (file_id, title, detail, severity, now, now),
    )
    return int(cur.lastrowid)


def _ensure_fts(con: sqlite3.Connection) -> None:
    try:
        con.execute("create virtual table if not exists case_fts using fts5(path, sha256, magic_type, text)")
    except sqlite3.OperationalError:
        con.execute("create table if not exists case_fts(rowid integer primary key, path text, sha256 text, magic_type text, text text)")


def _index_fts(con: sqlite3.Connection, file_id: int, analysis) -> None:
    text = json.dumps(
        {
            "strings": analysis.strings[:100],
            "iocs": analysis.iocs,
            "suspicious": analysis.suspicious,
            "explanation": analysis.explanation,
            "tags": analysis.tags,
            "notes": analysis.notes,
        },
        sort_keys=True,
    )
    con.execute("delete from case_fts where rowid = ?", (file_id,))
    con.execute(
        "insert into case_fts(rowid, path, sha256, magic_type, text) values (?, ?, ?, ?, ?)",
        (file_id, analysis.path, analysis.hashes.get("sha256", ""), analysis.magic_type, text),
    )
