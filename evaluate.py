#!/usr/bin/env python3
import argparse
import json
import os
from typing import Dict, List

from evaluation.evaluator import comparison_rows, evaluate_report, load_json
from evaluation.dataset_builder import build_candidate_dataset


def _write_json(path: str, data) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _format_value(value) -> str:
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def _print_metrics(result: Dict) -> None:
    fields = [
        "verdict_accuracy",
        "tp_precision",
        "tp_recall",
        "tp_f1",
        "required_tool_recall",
        "required_evidence_recall",
        "invalid_tool_call_rate",
        "structured_output_success_rate",
        "controlled_workflow_rate",
        "budget_exhaustion_rate",
        "critic_execution_rate",
        "critic_rejection_rate",
        "evidence_verified_rate",
        "fallback_usage_rate",
        "average_schema_rejections",
        "checkpoint_resume_rate",
        "average_agent_steps",
        "average_tokens",
        "average_latency_seconds",
        "estimated_cost",
    ]
    print(f"Run: {result.get('run_name') or '(unnamed)'}")
    print(
        f"Cases: {result['matched_cases']}/{result['cases_total']} matched, "
        f"{result['missing_cases']} missing, {result['extra_findings']} extra"
    )
    for field in fields:
        print(f"{field}: {_format_value(result[field])}")


def _markdown_table(rows: List[Dict]) -> str:
    if not rows:
        return ""
    headers = list(rows[0])
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(_format_value(row.get(key, "")) for key in headers) + " |")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate and compare CSAagent runs.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Evaluate one JSON report.")
    run_parser.add_argument("--labels", required=True, help="Ground-truth labels JSON.")
    run_parser.add_argument("--report", required=True, help="CSAagent JSON report.")
    run_parser.add_argument("--name", default="", help="Run or experiment name.")
    run_parser.add_argument(
        "--price-per-million-tokens",
        type=float,
        default=0.0,
        help="Blended model price used for estimated cost.",
    )
    run_parser.add_argument("--output", default="", help="Optional metrics JSON path.")

    compare_parser = subparsers.add_parser("compare", help="Compare metrics JSON files.")
    compare_parser.add_argument("metrics", nargs="+", help="Metrics JSON files.")
    compare_parser.add_argument("--output", default="", help="Optional comparison JSON path.")

    prepare_parser = subparsers.add_parser(
        "prepare", help="Build a diverse pending-review dataset from JSON reports."
    )
    prepare_parser.add_argument("reports", nargs="+", help="CSAagent JSON reports.")
    prepare_parser.add_argument("--name", required=True, help="Dataset name.")
    prepare_parser.add_argument("--limit", type=int, default=50, help="Maximum candidates.")
    prepare_parser.add_argument(
        "--source-root",
        default="",
        help="Optional source root used to attach a review excerpt around each finding.",
    )
    prepare_parser.add_argument("--output", required=True, help="Labels JSON path.")

    args = parser.parse_args()
    if args.command == "run":
        result = evaluate_report(
            load_json(args.labels),
            load_json(args.report),
            run_name=args.name,
            price_per_million_tokens=args.price_per_million_tokens,
        )
        _print_metrics(result)
        if args.output:
            _write_json(args.output, result)
    elif args.command == "compare":
        rows = comparison_rows(load_json(path) for path in args.metrics)
        print(_markdown_table(rows))
        if args.output:
            _write_json(args.output, rows)
    else:
        dataset = build_candidate_dataset(
            (load_json(path) for path in args.reports),
            name=args.name,
            limit=args.limit,
            source_root=args.source_root,
        )
        _write_json(args.output, dataset)
        print(f"Prepared {len(dataset['cases'])} pending-review cases: {args.output}")


if __name__ == "__main__":
    main()
