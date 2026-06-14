#!/usr/bin/env python3
import argparse
import json

from .trace_store import TraceStore


def main():
    parser = argparse.ArgumentParser(description="Attach evaluation metrics to an observed run.")
    parser.add_argument("--db", default="data/observability/traces.db")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--metrics", required=True)
    args = parser.parse_args()
    with open(args.metrics, "r", encoding="utf-8") as file:
        metrics = json.load(file)
    TraceStore(args.db).import_evaluation(args.run_id, metrics)
    print(f"Imported evaluation for run {args.run_id}")


if __name__ == "__main__":
    main()
