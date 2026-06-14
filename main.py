#!/usr/bin/env python3
"""
DefectAware - C/C++ defect detection and verification tool (CSA only)
"""
import argparse
import json
import os
import sys
from typing import List

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _count_verdicts(report, min_confidence: float):
    tp = 0
    uc = 0
    for item in report.reports:
        if item.confidence < min_confidence:
            continue
        if item.verdict == "TRUE_POSITIVE":
            tp += 1
        elif item.verdict == "UNCERTAIN":
            uc += 1
    return tp, uc


def _should_fail(report, fail_on: str, min_confidence: float) -> bool:
    tp, uc = _count_verdicts(report, min_confidence)
    has_analyzer_failure = len(report.analyzer_failures) > 0

    if fail_on == "never":
        return False
    if fail_on == "true_positive":
        return tp > 0
    if fail_on == "uncertain":
        return uc > 0
    if fail_on == "analyzer_failure":
        return has_analyzer_failure
    if fail_on == "true_positive_or_uncertain":
        return tp > 0 or uc > 0
    if fail_on == "any_issue":
        return tp > 0 or uc > 0 or has_analyzer_failure
    return False


def _resolve_output_formats(args, cfg) -> List[str]:
    if args.output_format:
        return args.output_format
    return cfg.get("report", {}).get("formats", ["json", "html"])


def _resolve_output_dir(args, cfg) -> str:
    if args.output_dir:
        return args.output_dir
    return cfg.get("report", {}).get("output_dir", "data/reports")


def main():
    parser = argparse.ArgumentParser(
        description="DefectAware: Clang Static Analyzer + Agent verification"
    )
    parser.add_argument("src_dir", help="C/C++ source directory path")
    parser.add_argument(
        "--config", default="config.yaml", help="config file path (default: config.yaml)"
    )
    parser.add_argument(
        "--compile-commands",
        default="",
        help="compile_commands.json path (optional, for accurate compile flags)",
    )
    parser.add_argument(
        "--output-format",
        nargs="+",
        choices=["json", "html", "csv"],
        default=None,
        help="report output formats; default from config.report.formats",
    )
    parser.add_argument(
        "--output-dir",
        default="",
        help="report output directory; default from config.report.output_dir",
    )
    parser.add_argument(
        "--summary-json",
        default="",
        help="optional path to write a machine-readable summary JSON",
    )
    parser.add_argument(
        "--ci",
        action="store_true",
        help="print concise CI-friendly logs",
    )
    parser.add_argument(
        "--fail-on",
        choices=[
            "never",
            "true_positive",
            "uncertain",
            "analyzer_failure",
            "true_positive_or_uncertain",
            "any_issue",
        ],
        default="never",
        help="when to return non-zero exit code in CI",
    )
    parser.add_argument(
        "--fail-confidence",
        type=float,
        default=0.0,
        help="minimum confidence used by fail-on rules for TP/UNCERTAIN",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.src_dir):
        print(f"[Error] source directory does not exist: {args.src_dir}")
        sys.exit(1)

    if not os.path.isfile(args.config):
        print(f"[Error] config file does not exist: {args.config}")
        print("Please copy and edit config.yaml, then fill in LLM key and tool paths.")
        sys.exit(1)

    from pipeline.report_generator import ReportGenerator
    from pipeline.runner import Runner

    print("DefectAware started")
    print(f"Source: {args.src_dir}")
    print(f"Config: {args.config}")
    print("-" * 60)

    runner = Runner(args.config)
    report = runner.run(args.src_dir, args.compile_commands)

    print("-" * 60)
    print("Analysis finished:")
    print(f"  Raw findings: {report.total_raw_findings}")
    print(f"  Analyzed: {report.total_analyzed}")
    print(f"  Analyzer failures: {len(report.analyzer_failures)}")
    print(f"  True positives: {report.true_positives}")
    print(f"  False positives: {report.false_positives}")
    print(f"  Uncertain: {report.uncertain}")
    print(f"  False positive rate: {report.false_positive_rate:.1%}")

    with open(args.config, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    output_dir = _resolve_output_dir(args, cfg)
    output_formats = _resolve_output_formats(args, cfg)

    generator = ReportGenerator(output_dir)
    files = generator.generate(report, output_formats)
    print("\nReports generated:")
    for f in files:
        print(f"  {f}")
        print(f"REPORT_FILE={os.path.abspath(f)}")

    tp_gate, uc_gate = _count_verdicts(report, args.fail_confidence)
    should_fail = _should_fail(report, args.fail_on, args.fail_confidence)

    summary = {
        "project_path": os.path.abspath(args.src_dir),
        "total_raw_findings": report.total_raw_findings,
        "total_analyzed": report.total_analyzed,
        "true_positives": report.true_positives,
        "false_positives": report.false_positives,
        "uncertain": report.uncertain,
        "analyzer_failures": len(report.analyzer_failures),
        "analyzer_failure_stats": report.analyzer_failure_stats,
        "fail_on": args.fail_on,
        "fail_confidence": args.fail_confidence,
        "gated_true_positives": tp_gate,
        "gated_uncertain": uc_gate,
        "should_fail": should_fail,
        "generated_files": [os.path.abspath(f) for f in files],
    }

    if args.summary_json:
        os.makedirs(os.path.dirname(os.path.abspath(args.summary_json)), exist_ok=True)
        with open(args.summary_json, "w", encoding="utf-8") as sf:
            json.dump(summary, sf, ensure_ascii=False, indent=2)
        print(f"SUMMARY_FILE={os.path.abspath(args.summary_json)}")

    if args.ci:
        print(
            "CSA_CI_SUMMARY "
            f"fail_on={args.fail_on} "
            f"threshold={args.fail_confidence} "
            f"tp_gated={tp_gate} "
            f"uc_gated={uc_gate} "
            f"analyzer_failures={len(report.analyzer_failures)} "
            f"should_fail={should_fail}"
        )

    if should_fail:
        print("[CI] Failing due to fail-on policy.")
        sys.exit(2)


if __name__ == "__main__":
    main()
