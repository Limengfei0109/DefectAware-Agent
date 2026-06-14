import os
from collections import defaultdict, deque
from typing import Dict, Iterable, List


def _case_id(finding: Dict, index: int) -> str:
    defect = str(finding.get("defect_id", "finding")).replace(".", "-")
    filename = os.path.basename(str(finding.get("file_path", "unknown")))
    stem = os.path.splitext(filename)[0]
    return f"{defect}-{stem}-{finding.get('line', 0)}-{index:03d}".lower()


def _source_excerpt(source_root: str, file_path: str, line: int, radius: int = 8) -> str:
    if not source_root:
        return ""
    candidate = file_path
    if not os.path.isabs(candidate):
        candidate = os.path.join(source_root, candidate)
    elif not os.path.isfile(candidate):
        candidate = os.path.join(source_root, file_path.lstrip("/\\"))
    if not os.path.isfile(candidate):
        return ""
    try:
        with open(candidate, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return ""
    start = max(1, int(line or 1) - radius)
    end = min(len(lines), int(line or 1) + radius)
    return "".join(f"{number:4d} | {lines[number - 1]}" for number in range(start, end + 1))


def _candidate_case(finding: Dict, index: int, source_root: str = "") -> Dict:
    match = {
        key: finding[key]
        for key in ("file_path", "line", "defect_id", "cwe")
        if finding.get(key) not in (None, "")
    }
    return {
        "id": _case_id(finding, index),
        "review_status": "pending",
        "match": match,
        "expected_verdict": "",
        "required_tools": [],
        "optional_tools": [],
        "required_evidence": [],
        "candidate_agent_verdict": finding.get("verdict", ""),
        "candidate_confidence": finding.get("confidence", 0.0),
        "review_context": {
            "message": finding.get("message", ""),
            "reasoning_chain": finding.get("reasoning_chain", []),
            "path_events": finding.get("path_events", []),
            "tool_calls_log": finding.get("tool_calls_log", []),
            "source_excerpt": _source_excerpt(
                source_root, str(finding.get("file_path", "")), int(finding.get("line", 1) or 1)
            ),
        },
        "notes": "",
    }


def build_candidate_dataset(
    reports: Iterable[Dict],
    name: str,
    limit: int = 50,
    source_root: str = "",
) -> Dict:
    grouped = defaultdict(deque)
    seen = set()
    for report in reports:
        for finding in report.get("findings", []):
            key = (
                os.path.normcase(os.path.normpath(str(finding.get("file_path", "")))),
                finding.get("line"),
                finding.get("defect_id"),
            )
            if key in seen:
                continue
            seen.add(key)
            grouped[str(finding.get("defect_id", "unknown"))].append(finding)

    selected: List[Dict] = []
    groups = deque(sorted(grouped))
    while groups and len(selected) < max(1, limit):
        defect_id = groups.popleft()
        queue = grouped[defect_id]
        if queue:
            selected.append(queue.popleft())
        if queue:
            groups.append(defect_id)

    return {
        "name": name,
        "version": 1,
        "cases": [
            _candidate_case(finding, index, source_root)
            for index, finding in enumerate(selected, start=1)
        ],
    }
