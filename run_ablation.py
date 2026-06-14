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
    parser = argparse.ArgumentParser(description="Run CSAagent ablation variants.")
    parser.add_argument("src_dir")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--compile-commands", default="")
    parser.add_argument("--output-dir", default="data/experiments")
    parser.add_argument("--modes", nargs="+", default=DEFAULT_MODES)
    parser.add_argument("--labels", default="", help="Reviewed labels JSON for automatic evaluation.")
    parser.add_argument("--price-per-million-tokens", type=float, default=0.0)
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        base_config = yaml.safe_load(f)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    experiment_dir = os.path.abspath(os.path.join(args.output_dir, stamp))
    os.makedirs(experiment_dir, exist_ok=True)
    manifest = {
        "created_at": stamp,
        "src_dir": os.path.abspath(args.src_dir),
        "compile_commands": os.path.abspath(args.compile_commands)
        if args.compile_commands
        else "",
        "runs": [],
    }
    labels = load_json(args.labels) if args.labels else None
    evaluated_results = []

    for mode in args.modes:
        run_dir = os.path.join(experiment_dir, mode)
        os.makedirs(run_dir, exist_ok=True)
        config = deepcopy(base_config)
        config.setdefault("agent", {})["mode"] = mode
        config.setdefault("reliability", {})["checkpoint_namespace"] = f"{stamp}/{mode}"
        config.setdefault("report", {})["output_dir"] = run_dir
        config["report"]["formats"] = ["json"]
        config_path = os.path.join(run_dir, "config.yaml")
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False)

        command = [
            sys.executable,
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.py"),
            args.src_dir,
            "--config",
            config_path,
            "--output-dir",
            run_dir,
            "--output-format",
            "json",
        ]
        if args.compile_commands:
            command.extend(["--compile-commands", args.compile_commands])
        print(f"[Ablation] Running {mode}")
        result = subprocess.run(command)
        reports = sorted(
            (
                os.path.join(run_dir, name)
                for name in os.listdir(run_dir)
                if name.startswith("report_") and name.endswith(".json")
            ),
            key=os.path.getmtime,
            reverse=True,
        )
        run_info = {
            "mode": mode,
            "return_code": result.returncode,
            "report": reports[0] if reports else "",
            "config": config_path,
        }
        if labels and reports:
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
            evaluated_results.append(metrics)
        manifest["runs"].append(run_info)

    manifest_path = os.path.join(experiment_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    if evaluated_results:
        comparison = comparison_rows(evaluated_results)
        comparison_path = os.path.join(experiment_dir, "comparison.json")
        with open(comparison_path, "w", encoding="utf-8") as f:
            json.dump(comparison, f, ensure_ascii=False, indent=2)
        print(f"Ablation comparison: {comparison_path}")
    print(f"Ablation manifest: {manifest_path}")


if __name__ == "__main__":
    main()
