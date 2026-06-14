#!/usr/bin/env python3
import argparse
import json
import os

import yaml

from agent import build_verification_engine
from context import ContextBuilder
from models.finding import PathEvent, RawFinding
from models.report import FinalReport
from pipeline.report_generator import ReportGenerator
from observability import record_report_if_enabled
from pipeline.checkpoint import CheckpointStore


def _raw_finding(item: dict, project_root: str) -> RawFinding:
    file_path = item["file_path"]
    if not os.path.isabs(file_path):
        file_path = os.path.realpath(os.path.join(project_root, file_path))
    return RawFinding(
        tool=item.get("tool", "seed-report"),
        file_path=file_path,
        line=int(item.get("line", 0)),
        column=int(item.get("column", 0)),
        severity=item.get("severity", "warning"),
        defect_id=item.get("defect_id", ""),
        cwe=item.get("cwe"),
        message=item.get("message", ""),
        path_events=[
            PathEvent(
                file_path=event.get("file_path", ""),
                line=int(event.get("line", 0)),
                column=int(event.get("column", 0)),
                message=event.get("message", ""),
                event_kind=event.get("event_kind", ""),
                details=event.get("details", {}),
            )
            for event in item.get("path_events", [])
        ],
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Agent against a seed findings report.")
    parser.add_argument("--report", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--compile-commands", default="")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    with open(args.report, "r", encoding="utf-8") as f:
        seed = json.load(f)
    with open(args.config, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    project_root = seed.get("project_path", "")
    tools = config.get("tools", {})
    analysis = config.get("analysis", {})
    context_builder = ContextBuilder(
        tools.get("libclang_path", ""),
        analysis.get("compile_args", ["-std=c++17"]),
    )
    context_builder.configure_compile_commands(args.compile_commands)
    agent = build_verification_engine(
        config.get("llm", {}),
        config.get("agent", {}),
        tools.get("libclang_path", ""),
        analysis.get("compile_args", ["-std=c++17"]),
    )
    agent.configure_environment(project_root, args.compile_commands)
    reliability = config.get("reliability", {})
    checkpoints = (
        CheckpointStore(
            reliability.get("checkpoint_dir", "data/checkpoints"),
            namespace=CheckpointStore.namespace_for(config),
        )
        if reliability.get("checkpoint_enabled", True)
        else None
    )

    reports = []
    for index, item in enumerate(seed.get("findings", []), start=1):
        print(f"[{index}/{len(seed.get('findings', []))}] {item.get('file_path')}:{item.get('line')}")
        enriched = context_builder.enrich(_raw_finding(item, project_root))
        cached = checkpoints.load(enriched) if checkpoints else None
        if cached:
            reports.append(checkpoints.restore_report(enriched, cached))
            print("  resumed from checkpoint")
            continue
        report = agent.verify(enriched)
        reports.append(report)
        if checkpoints:
            checkpoints.save(enriched, checkpoints.report_payload(report))

    final = FinalReport(
        project_path=project_root,
        total_raw_findings=len(reports),
        total_analyzed=len(reports),
        true_positives=sum(item.verdict == "TRUE_POSITIVE" for item in reports),
        false_positives=sum(item.verdict == "FALSE_POSITIVE" for item in reports),
        uncertain=sum(item.verdict == "UNCERTAIN" for item in reports),
        false_positive_rate=(
            sum(item.verdict == "FALSE_POSITIVE" for item in reports) / len(reports)
            if reports
            else 0.0
        ),
        reports=reports,
    )
    run_id = record_report_if_enabled(
        final,
        config,
        {
            "seed_report": os.path.abspath(args.report),
            "compile_commands": os.path.abspath(args.compile_commands)
            if args.compile_commands
            else "",
        },
    )
    if run_id:
        print(f"Trace run_id: {run_id}")
    files = ReportGenerator(args.output_dir).generate(final, ["json"])
    print(f"Agent report: {os.path.abspath(files[0])}")


if __name__ == "__main__":
    main()
