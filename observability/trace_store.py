import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Dict, Iterable, Optional

from models.report import FinalReport


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=False)


class TraceStore:
    """Persist Agent runs and normalized traces in SQLite."""

    def __init__(self, path: str = "data/observability/traces.db"):
        self.path = os.path.abspath(path)
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @contextmanager
    def _connection(self):
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    project_path TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    model TEXT NOT NULL,
                    agent_mode TEXT NOT NULL,
                    total_findings INTEGER NOT NULL,
                    true_positives INTEGER NOT NULL,
                    false_positives INTEGER NOT NULL,
                    uncertain INTEGER NOT NULL,
                    total_tokens INTEGER NOT NULL,
                    total_latency_seconds REAL NOT NULL,
                    failure_count INTEGER NOT NULL,
                    metadata_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                    file_path TEXT NOT NULL,
                    line INTEGER NOT NULL,
                    defect_id TEXT NOT NULL,
                    cwe TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    tokens INTEGER NOT NULL,
                    latency_seconds REAL NOT NULL,
                    agent_steps INTEGER NOT NULL,
                    structured_output_success INTEGER NOT NULL,
                    workflow_route TEXT NOT NULL,
                    budget_exhausted INTEGER NOT NULL,
                    evidence_verified INTEGER NOT NULL DEFAULT 0,
                    fallback_used INTEGER NOT NULL DEFAULT 0,
                    schema_rejections INTEGER NOT NULL DEFAULT 0,
                    resumed_from_checkpoint INTEGER NOT NULL DEFAULT 0,
                    failure_reason TEXT NOT NULL,
                    reasoning_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id INTEGER NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
                    sequence INTEGER NOT NULL,
                    stage TEXT NOT NULL,
                    prompt TEXT NOT NULL,
                    observation TEXT NOT NULL,
                    latency_seconds REAL NOT NULL,
                    tokens INTEGER NOT NULL,
                    detail_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tool_calls (
                    tool_call_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id INTEGER NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
                    sequence INTEGER NOT NULL,
                    tool_name TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    args_json TEXT NOT NULL,
                    observation TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS evaluations (
                    evaluation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                    imported_at TEXT NOT NULL,
                    metrics_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
                CREATE INDEX IF NOT EXISTS idx_events_finding ON events(finding_id);
                CREATE INDEX IF NOT EXISTS idx_tools_finding ON tool_calls(finding_id);
                """
            )
            existing = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(findings)").fetchall()
            }
            for name, definition in (
                ("evidence_verified", "INTEGER NOT NULL DEFAULT 0"),
                ("fallback_used", "INTEGER NOT NULL DEFAULT 0"),
                ("schema_rejections", "INTEGER NOT NULL DEFAULT 0"),
                ("resumed_from_checkpoint", "INTEGER NOT NULL DEFAULT 0"),
            ):
                if name not in existing:
                    connection.execute(f"ALTER TABLE findings ADD COLUMN {name} {definition}")

    def record_report(self, report: FinalReport, metadata: Optional[Dict] = None) -> str:
        metadata = dict(metadata or {})
        run_id = str(metadata.get("run_id") or uuid.uuid4())
        provider = str(metadata.get("provider", ""))
        model = str(metadata.get("model", ""))
        agent_mode = str(metadata.get("agent_mode", ""))
        total_tokens = sum(item.llm_tokens_used for item in report.reports)
        total_latency = sum(item.processing_time for item in report.reports)
        failure_count = len(report.analyzer_failures) + sum(bool(item.error) for item in report.reports)
        created_at = report.generated_at or datetime.now(timezone.utc).isoformat()

        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    created_at,
                    report.project_path,
                    provider,
                    model,
                    agent_mode,
                    report.total_analyzed,
                    report.true_positives,
                    report.false_positives,
                    report.uncertain,
                    total_tokens,
                    total_latency,
                    failure_count,
                    _json(metadata),
                ),
            )
            for item in report.reports:
                raw = item.finding.raw
                failure_reason = self._failure_reason(item)
                cursor = connection.execute(
                    """
                    INSERT INTO findings (
                        run_id, file_path, line, defect_id, cwe, verdict, confidence,
                        tokens, latency_seconds, agent_steps, structured_output_success,
                        workflow_route, budget_exhausted, evidence_verified, fallback_used,
                        schema_rejections, resumed_from_checkpoint, failure_reason, reasoning_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        raw.file_path,
                        raw.line,
                        raw.defect_id,
                        raw.cwe or "",
                        item.verdict,
                        item.confidence,
                        item.llm_tokens_used,
                        item.processing_time,
                        item.agent_steps,
                        int(item.structured_output_success),
                        item.workflow_route,
                        int(item.budget_exhausted),
                        int(item.evidence_verified),
                        int(item.fallback_used),
                        item.schema_rejections,
                        int(item.resumed_from_checkpoint),
                        failure_reason,
                        _json(item.reasoning_chain),
                    ),
                )
                finding_id = cursor.lastrowid
                self._record_events(connection, finding_id, item.workflow_trace)
                self._record_tools(connection, finding_id, item.tool_calls_log)
            for failure in report.analyzer_failures:
                metadata.setdefault("analyzer_failures", []).append(
                    {
                        "analyzer": failure.analyzer,
                        "category": failure.error_category,
                        "summary": failure.error_summary,
                    }
                )
            connection.execute(
                "UPDATE runs SET metadata_json = ? WHERE run_id = ?",
                (_json(metadata), run_id),
            )
        return run_id

    @staticmethod
    def _record_events(connection, finding_id: int, events: Iterable[Dict]) -> None:
        for sequence, event in enumerate(events, start=1):
            detail = event.get("detail", {})
            connection.execute(
                """
                INSERT INTO events (
                    finding_id, sequence, stage, prompt, observation,
                    latency_seconds, tokens, detail_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    sequence,
                    str(event.get("stage", "")),
                    str(detail.get("prompt", "")),
                    str(detail.get("observation", "")),
                    float(detail.get("latency_seconds", 0.0) or 0.0),
                    int(detail.get("tokens_used", 0) or 0),
                    _json(detail),
                ),
            )

    @staticmethod
    def _failure_reason(item) -> str:
        if item.error:
            return f"execution_error: {item.error}"
        if item.budget_exhausted:
            return "budget_exhausted"
        evidence_events = [
            event
            for event in item.workflow_trace
            if event.get("stage") == "evidence_verifier"
        ]
        if evidence_events and evidence_events[-1].get("detail", {}).get("supported") is False:
            return "evidence_verifier_rejected"
        critic_events = [
            event
            for event in item.workflow_trace
            if event.get("stage") == "critic_complete"
        ]
        if critic_events and critic_events[-1].get("detail", {}).get("supported") is False:
            return "critic_rejected"
        if not item.structured_output_success:
            return "structured_output_failure"
        if item.verdict == "UNCERTAIN":
            return "insufficient_evidence"
        return ""

    @staticmethod
    def _record_tools(connection, finding_id: int, calls: Iterable[Dict]) -> None:
        for sequence, call in enumerate(calls, start=1):
            observation = str(call.get("observation", ""))
            success = not observation.startswith(("[Error]", "[Tool error]"))
            connection.execute(
                """
                INSERT INTO tool_calls (
                    finding_id, sequence, tool_name, success, args_json, observation
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    sequence,
                    str(call.get("tool", "")),
                    int(success),
                    _json(call.get("args", {})),
                    observation,
                ),
            )

    def import_evaluation(self, run_id: str, metrics: Dict) -> None:
        with self._connection() as connection:
            exists = connection.execute(
                "SELECT 1 FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if not exists:
                raise ValueError(f"Unknown run_id: {run_id}")
            connection.execute(
                "INSERT INTO evaluations (run_id, imported_at, metrics_json) VALUES (?, ?, ?)",
                (run_id, datetime.now(timezone.utc).isoformat(), _json(metrics)),
            )

    def query(self, sql: str, parameters=()) -> list:
        with self._connection() as connection:
            return [dict(row) for row in connection.execute(sql, parameters).fetchall()]
