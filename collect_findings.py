#!/usr/bin/env python3
import argparse
import json
import os
from datetime import datetime

import yaml

from analyzers import ClangStaticAnalyzer


def _finding_to_dict(finding) -> dict:
    return {
        "verdict": "",
        "confidence": 0.0,
        "tool": finding.tool,
        "file_path": finding.file_path,
        "line": finding.line,
        "column": finding.column,
        "severity": finding.severity,
        "defect_id": finding.defect_id,
        "cwe": finding.cwe,
        "message": finding.message,
        "path_events": [
            {
                "file_path": event.file_path,
                "line": event.line,
                "column": event.column,
                "message": event.message,
                "event_kind": event.event_kind,
                "details": event.details,
            }
            for event in finding.path_events
        ],
        "reasoning_chain": [],
        "tool_calls_log": [],
        "processing_time": 0.0,
        "llm_tokens_used": 0,
        "agent_steps": 0,
        "structured_output_success": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect Clang Static Analyzer findings without calling an LLM."
    )
    parser.add_argument("src_dir")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--compile-commands", default="")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    tools = config.get("tools", {})
    analysis = config.get("analysis", {})
    analyzer = ClangStaticAnalyzer(
        clang_path=tools.get("clang_sa", "clang"),
        extra_args=analysis.get("clang_sa_extra_args", []),
        skip_dirs=analysis.get("skip_dirs", []),
        file_extensions=analysis.get("file_extensions", []),
        checkers=tools.get("clang_sa_checkers", []),
        show_failures=True,
    )
    findings = analyzer.run(args.src_dir, args.compile_commands)
    payload = {
        "project_path": os.path.abspath(args.src_dir),
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "total_raw_findings": len(findings),
            "analyzer_failure_count": len(analyzer.last_failures),
        },
        "findings": [_finding_to_dict(finding) for finding in findings],
        "analysis_failures": [
            {
                "analyzer": failure.analyzer,
                "file_path": failure.file_path,
                "error_category": failure.error_category,
                "error_summary": failure.error_summary,
                "stderr_excerpt": failure.stderr_excerpt,
                "include_trace": failure.include_trace,
                "return_code": failure.return_code,
            }
            for failure in analyzer.last_failures
        ],
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    print(
        f"Collected {len(findings)} findings and "
        f"{len(analyzer.last_failures)} analyzer failures: {args.output}"
    )


if __name__ == "__main__":
    main()
