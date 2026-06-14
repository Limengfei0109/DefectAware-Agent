from typing import Dict

from models.report import FinalReport

from .trace_store import TraceStore


def record_report_if_enabled(
    report: FinalReport, config: Dict, extra_metadata: Dict = None
) -> str:
    observability = config.get("observability", {})
    if not observability.get("enabled", False):
        return ""
    llm = config.get("llm", {})
    agent = config.get("agent", {})
    metadata = {
        "provider": llm.get("provider", ""),
        "model": llm.get("model", ""),
        "agent_mode": agent.get("mode", ""),
        "temperature": llm.get("temperature"),
        "max_tokens": llm.get("max_tokens"),
    }
    metadata.update(extra_metadata or {})
    run_id = TraceStore(
        observability.get("db_path", "data/observability/traces.db")
    ).record_report(report, metadata)
    report.run_id = run_id
    return run_id
