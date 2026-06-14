import hashlib
import json
import os
from typing import Dict, Optional

from models.report import DefectReport


class CheckpointStore:
    """Persist completed finding reports so interrupted runs can resume."""

    def __init__(self, directory: str, namespace: str = ""):
        self.directory = os.path.abspath(directory)
        self.namespace = namespace
        os.makedirs(self.directory, exist_ok=True)

    @staticmethod
    def namespace_for(config: Dict) -> str:
        llm = {
            key: value
            for key, value in config.get("llm", {}).items()
            if key not in {"api_key", "api_key_env"}
        }
        payload = {
            "llm": llm,
            "agent": config.get("agent", {}),
            "explicit": config.get("reliability", {}).get("checkpoint_namespace", ""),
        }
        return hashlib.sha256(
            json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()

    def key(self, finding) -> str:
        raw = finding.raw
        fingerprint = ""
        try:
            with open(raw.file_path, "rb") as file:
                fingerprint = hashlib.sha256(file.read()).hexdigest()
        except OSError:
            pass
        identity = (
            f"{self.namespace}|{raw.file_path}|{fingerprint}|{raw.line}|"
            f"{raw.defect_id}|{raw.cwe or ''}"
        )
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()

    def load(self, finding) -> Optional[Dict]:
        path = os.path.join(self.directory, self.key(finding) + ".json")
        if not os.path.isfile(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as file:
                return json.load(file)
        except (OSError, json.JSONDecodeError):
            return None

    def save(self, finding, payload: Dict) -> None:
        path = os.path.join(self.directory, self.key(finding) + ".json")
        temporary = path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as file:
            json.dump(payload, file, ensure_ascii=False, indent=2)
        os.replace(temporary, path)

    @staticmethod
    def report_payload(report: DefectReport) -> Dict:
        return {
            "verdict": report.verdict,
            "confidence": report.confidence,
            "reasoning_chain": report.reasoning_chain,
            "tool_calls_log": report.tool_calls_log,
            "fixed_code": report.fixed_code,
            "fix_explanation": report.fix_explanation,
            "processing_time": report.processing_time,
            "llm_tokens_used": report.llm_tokens_used,
            "agent_steps": report.agent_steps,
            "structured_output_success": report.structured_output_success,
            "workflow_mode": report.workflow_mode,
            "workflow_route": report.workflow_route,
            "workflow_trace": report.workflow_trace,
            "budget_exhausted": report.budget_exhausted,
            "evidence_verified": report.evidence_verified,
            "fallback_used": report.fallback_used,
            "schema_rejections": report.schema_rejections,
            "error": report.error,
        }

    @staticmethod
    def restore_report(finding, payload: Dict) -> DefectReport:
        fields = {
            name: payload[name]
            for name in (
                "verdict", "confidence", "reasoning_chain", "tool_calls_log",
                "fixed_code", "fix_explanation", "processing_time", "llm_tokens_used",
                "agent_steps", "structured_output_success", "workflow_mode",
                "workflow_route", "workflow_trace", "budget_exhausted",
                "evidence_verified", "fallback_used", "schema_rejections", "error",
            )
            if name in payload
        }
        fields["resumed_from_checkpoint"] = True
        return DefectReport(finding=finding, **fields)
