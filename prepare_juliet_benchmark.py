#!/usr/bin/env python3
import argparse
import json
import os
import re
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Tuple


CWE_TO_DEFECT = {
    "CWE369": ("core.DivideZero", "CWE-369"),
    "CWE401": ("unix.Malloc", "CWE-401"),
    "CWE415": ("cplusplus.DoubleFree", "CWE-415"),
    "CWE476": ("core.NullDereference", "CWE-476"),
    "CWE562": ("core.StackAddressEscape", "CWE-562"),
    "CWE690": ("core.NullDereference", "CWE-476"),
}


def _next_code_line(lines: List[str], start: int) -> Tuple[int, str]:
    for index in range(start, min(len(lines), start + 8)):
        stripped = lines[index].strip()
        if stripped and not stripped.startswith(("/*", "*", "//", "*/")):
            return index + 1, stripped
    return start + 1, ""


def _function_context(lines: List[str], line_index: int) -> str:
    for index in range(line_index, max(-1, line_index - 80), -1):
        text = lines[index]
        match = re.search(r"\b(\w*(?:bad|goodG2B|goodB2G)\w*)\s*\([^;]*\)", text)
        if match:
            return match.group(1)
    return ""


def _extract_cases(path: str, juliet_root: str) -> List[Dict]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    name = os.path.basename(path)
    cwe_match = re.match(r"(CWE\d+)", name)
    if not cwe_match or cwe_match.group(1) not in CWE_TO_DEFECT:
        return []
    defect_id, cwe = CWE_TO_DEFECT[cwe_match.group(1)]
    cases = []
    for index, line in enumerate(lines):
        if "POTENTIAL FLAW" not in line:
            continue
        function_name = _function_context(lines, index)
        if not function_name:
            continue
        expected = "TRUE_POSITIVE" if "bad" in function_name.lower() else "FALSE_POSITIVE"
        finding_line, snippet = _next_code_line(lines, index + 1)
        if not snippet:
            continue
        cases.append(
            {
                "file_path": os.path.relpath(os.path.realpath(path), juliet_root),
                "line": finding_line,
                "column": 1,
                "severity": "warning",
                "defect_id": defect_id,
                "cwe": cwe,
                "message": f"Juliet benchmark candidate in {function_name}: {snippet}",
                "expected_verdict": expected,
                "function_name": function_name,
                "snippet": snippet,
            }
        )
    return cases


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a reviewed Agent benchmark from NIST Juliet good/bad cases."
    )
    parser.add_argument("juliet_root")
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--labels-output", required=True)
    parser.add_argument("--report-output", required=True)
    args = parser.parse_args()

    testcases = os.path.join(os.path.realpath(args.juliet_root), "testcases")
    candidates = []
    for root, _, files in os.walk(testcases):
        for name in sorted(files):
            if not name.endswith("_01.c"):
                continue
            candidates.extend(_extract_cases(os.path.join(root, name), os.path.realpath(args.juliet_root)))

    # Round-robin across CWE categories while alternating TP and FP.
    grouped = defaultdict(lambda: {"TRUE_POSITIVE": deque(), "FALSE_POSITIVE": deque()})
    for item in candidates:
        grouped[item["cwe"]][item["expected_verdict"]].append(item)
    categories = deque(sorted(grouped))
    selected = []
    while categories and len(selected) < args.limit:
        cwe = categories.popleft()
        queues = grouped[cwe]
        for verdict in ("TRUE_POSITIVE", "FALSE_POSITIVE"):
            if queues[verdict] and len(selected) < args.limit:
                selected.append(queues[verdict].popleft())
        if queues["TRUE_POSITIVE"] or queues["FALSE_POSITIVE"]:
            categories.append(cwe)

    labels = {
        "name": "nist-juliet-agent-v1",
        "version": 1,
        "cases": [],
    }
    report = {
        "project_path": os.path.realpath(args.juliet_root),
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {"total_raw_findings": len(selected), "analyzer_failure_count": 0},
        "findings": [],
        "analysis_failures": [],
    }
    for index, item in enumerate(selected, start=1):
        case_id = f"juliet-{index:03d}"
        labels["cases"].append(
            {
                "id": case_id,
                "review_status": "reviewed",
                "match": {
                    "file_path": item["file_path"],
                    "line": item["line"],
                    "defect_id": item["defect_id"],
                    "cwe": item["cwe"],
                },
                "expected_verdict": item["expected_verdict"],
                "required_tools": ["get_function_context"],
                "optional_tools": [
                    "get_source_code",
                    "find_variable_definition",
                    "search_null_checks",
                    "get_callees",
                ],
                "required_evidence": [],
                "notes": (
                    f"NIST Juliet official {'bad' if item['expected_verdict'] == 'TRUE_POSITIVE' else 'good'} "
                    f"path in {item['function_name']}."
                ),
            }
        )
        report["findings"].append(
            {
                "verdict": "",
                "confidence": 0.0,
                "tool": "juliet-ground-truth",
                "file_path": item["file_path"],
                "line": item["line"],
                "column": item["column"],
                "severity": item["severity"],
                "defect_id": item["defect_id"],
                "cwe": item["cwe"],
                "message": item["message"],
                "path_events": [],
                "reasoning_chain": [],
                "tool_calls_log": [],
                "processing_time": 0.0,
                "llm_tokens_used": 0,
                "agent_steps": 0,
                "structured_output_success": False,
            }
        )

    for path, payload in (
        (args.labels_output, labels),
        (args.report_output, report),
    ):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    print(
        f"Prepared {len(selected)} reviewed Juliet cases: "
        f"{len([x for x in selected if x['expected_verdict'] == 'TRUE_POSITIVE'])} TP, "
        f"{len([x for x in selected if x['expected_verdict'] == 'FALSE_POSITIVE'])} FP"
    )


if __name__ == "__main__":
    main()
