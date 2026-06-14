#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
from copy import deepcopy
from datetime import datetime

import yaml

from evaluation.evaluator import comparison_rows, evaluate_report, load_json
from observability import TraceStore


DEFAULT_MODES = [
    "direct_llm",
    "context_only",
    "react_tools",
    "react_specialized",
    "controlled_workflow",
]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Agent ablations against seed findings.")
    parser.add_argument("--report", required=True)
    parser.add_argument("--labels", required=True)
    parser.add_argument("--config", default="configs/config.ndk.yaml")
    parser.add_argument("--compile-commands", default="")
    parser.add_argument("--output-dir", default="data/experiments")
    parser.add_argument("--modes", nargs="+", default=DEFAULT_MODES)
    parser.add_argument("--price-per-million-tokens", type=float, default=0.0)
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        base_config = yaml.safe_load(f)
    labels = load_json(args.labels)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    experiment_dir = os.path.abspath(os.path.join(args.output_dir, f"seed-{stamp}"))
    os.makedirs(experiment_dir, exist_ok=True)
    results = []
    runs = []

    for mode in args.modes:
        run_dir = os.path.join(experiment_dir, mode)
        os.makedirs(run_dir, exist_ok=True)
        config = deepcopy(base_config)
        config.setdefault("agent", {})["mode"] = mode
        config.setdefault("reliability", {})["checkpoint_namespace"] = f"{stamp}/{mode}"
        config_path = os.path.join(run_dir, "config.yaml")
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False)
        command = [
            sys.executable,
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "run_agent_report.py"),
            "--report",
            args.report,
            "--config",
            config_path,
            "--output-dir",
            run_dir,
        ]
        if args.compile_commands:
            command.extend(["--compile-commands", args.compile_commands])
        print(f"[Seed Ablation] Running {mode}")
        completed = subprocess.run(command)
        reports = sorted(
            (
                os.path.join(run_dir, name)
                for name in os.listdir(run_dir)
                if name.startswith("report_") and name.endswith(".json")
            ),
            key=os.path.getmtime,
            reverse=True,
        )
        run_info = {"mode": mode, "return_code": completed.returncode, "report": ""}
        if reports:
            run_info["report"] = reports[0]
            metrics = evaluate_report(
                labels,
                load_json(reports[0]),
                run_name=mode,
                price_per_million_tokens=args.price_per_million_tokens,
            )
            metrics_path = os.path.join(run_dir, "metrics.json")
            with open(metrics_path, "w", encoding="utf-8") as f:
                json.dump(metrics, f, ensure_ascii=False, indent=2)
            run_report = load_json(reports[0])
            run_id = run_report.get("run_id", "")
            observability = config.get("observability", {})
            if run_id and observability.get("enabled", False):
                TraceStore(
                    observability.get("db_path", "data/observability/traces.db")
                ).import_evaluation(run_id, metrics)
            run_info["metrics"] = metrics_path
            results.append(metrics)
        runs.append(run_info)

    comparison = comparison_rows(results)
    with open(os.path.join(experiment_dir, "comparison.json"), "w", encoding="utf-8") as f:
        json.dump(comparison, f, ensure_ascii=False, indent=2)
    with open(os.path.join(experiment_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump({"runs": runs}, f, ensure_ascii=False, indent=2)
    print(json.dumps(comparison, ensure_ascii=False, indent=2))
    print(f"Seed ablation results: {experiment_dir}")


if __name__ == "__main__":
    main()
