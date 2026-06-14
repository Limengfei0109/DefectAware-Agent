import json
import os
from collections import Counter
from typing import Dict, Iterable, List, Optional, Tuple


VALID_VERDICTS = {"TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN"}


def load_json(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _normalized_path(path: str) -> str:
    return os.path.normcase(os.path.normpath(path or "")).replace("\\", "/")


def _path_matches(actual: str, expected: str) -> bool:
    actual_norm = _normalized_path(actual)
    expected_norm = _normalized_path(expected)
    return actual_norm == expected_norm or actual_norm.endswith("/" + expected_norm)


def _matches(finding: Dict, match: Dict) -> bool:
    if match.get("file_path") and not _path_matches(
        finding.get("file_path", ""), match["file_path"]
    ):
        return False
    for key in ("line", "defect_id", "cwe"):
        if key in match and finding.get(key) != match[key]:
            return False
    return True


def _find_finding(findings: List[Dict], match: Dict, used: set) -> Optional[int]:
    for index, finding in enumerate(findings):
        if index not in used and _matches(finding, match):
            return index
    return None


def _called_tools(finding: Dict) -> List[str]:
    return [
        str(item.get("tool", ""))
        for item in finding.get("tool_calls_log", [])
        if item.get("tool")
    ]


def _evidence_text(finding: Dict) -> str:
    sections = [str(item) for item in finding.get("reasoning_chain", [])]
    sections.extend(
        str(item.get("observation", ""))
        for item in finding.get("tool_calls_log", [])
    )
    return "\n".join(sections).lower()


def _round_metrics(value):
    if isinstance(value, float):
        return round(value, 4)
    if isinstance(value, dict):
        return {key: _round_metrics(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_round_metrics(item) for item in value]
    return value


def evaluate_report(
    labels: Dict,
    report: Dict,
    run_name: str = "",
    price_per_million_tokens: float = 0.0,
) -> Dict:
    all_cases = labels.get("cases", [])
    cases = [
        case
        for case in all_cases
        if case.get("review_status", "reviewed") == "reviewed"
    ]
    findings = report.get("findings", [])
    used_findings = set()
    case_results = []
    confusion = Counter()
    verdict_correct = 0
    predicted_positive = 0
    actual_positive = 0
    true_positive = 0
    required_tools_total = 0
    required_tools_found = 0
    useful_tool_calls = 0
    total_tool_calls = 0
    required_evidence_total = 0
    required_evidence_found = 0
    total_tokens = 0
    total_latency = 0.0
    total_steps = 0
    structured_successes = 0
    workflow_cases = 0
    budget_exhaustions = 0
    critic_executions = 0
    critic_rejections = 0
    evidence_verified = 0
    fallback_uses = 0
    schema_rejections = 0
    checkpoint_resumes = 0
    matched = 0
    by_defect: Dict[str, Counter] = {}

    for case in cases:
        finding_index = _find_finding(findings, case.get("match", {}), used_findings)
        expected = case.get("expected_verdict", "UNCERTAIN")
        if expected not in VALID_VERDICTS:
            raise ValueError(f"Invalid expected_verdict in case {case.get('id')}: {expected}")

        if finding_index is None:
            case_results.append(
                {
                    "id": case.get("id", ""),
                    "status": "missing",
                    "expected_verdict": expected,
                    "predicted_verdict": None,
                }
            )
            confusion[(expected, "MISSING")] += 1
            if expected == "TRUE_POSITIVE":
                actual_positive += 1
            continue

        used_findings.add(finding_index)
        matched += 1
        finding = findings[finding_index]
        predicted = finding.get("verdict", "UNCERTAIN")
        if predicted not in VALID_VERDICTS:
            predicted = "UNCERTAIN"
        correct = predicted == expected
        verdict_correct += int(correct)
        confusion[(expected, predicted)] += 1

        if expected == "TRUE_POSITIVE":
            actual_positive += 1
        if predicted == "TRUE_POSITIVE":
            predicted_positive += 1
        if expected == predicted == "TRUE_POSITIVE":
            true_positive += 1

        required_tools = set(case.get("required_tools", []))
        allowed_tools = required_tools | set(case.get("optional_tools", []))
        called_tools = _called_tools(finding)
        called_tool_set = set(called_tools)
        found_tools = required_tools & called_tool_set
        required_tools_total += len(required_tools)
        required_tools_found += len(found_tools)
        total_tool_calls += len(called_tools)
        useful_tool_calls += sum(
            1 for tool in called_tools if not allowed_tools or tool in allowed_tools
        )

        evidence_text = _evidence_text(finding)
        required_evidence = [str(item).lower() for item in case.get("required_evidence", [])]
        found_evidence = [item for item in required_evidence if item in evidence_text]
        required_evidence_total += len(required_evidence)
        required_evidence_found += len(found_evidence)

        tokens = int(finding.get("llm_tokens_used", 0) or 0)
        latency = float(finding.get("processing_time", 0.0) or 0.0)
        steps = int(finding.get("agent_steps", 0) or 0)
        total_tokens += tokens
        total_latency += latency
        total_steps += steps
        structured_successes += int(bool(finding.get("structured_output_success", False)))
        is_workflow = finding.get("workflow_mode") == "controlled_workflow"
        workflow_cases += int(is_workflow)
        if is_workflow:
            budget_exhaustions += int(bool(finding.get("budget_exhausted", False)))
            critic_events = [
                event
                for event in finding.get("workflow_trace", [])
                if event.get("stage") == "critic_complete"
            ]
            if critic_events:
                critic_executions += 1
                critic_rejections += int(
                    critic_events[-1].get("detail", {}).get("supported") is False
                )
        evidence_verified += int(bool(finding.get("evidence_verified", False)))
        fallback_uses += int(bool(finding.get("fallback_used", False)))
        schema_rejections += int(finding.get("schema_rejections", 0) or 0)
        checkpoint_resumes += int(bool(finding.get("resumed_from_checkpoint", False)))

        defect_id = str(finding.get("defect_id", "unknown"))
        stats = by_defect.setdefault(defect_id, Counter())
        stats["total"] += 1
        stats["correct"] += int(correct)

        case_results.append(
            {
                "id": case.get("id", ""),
                "status": "matched",
                "expected_verdict": expected,
                "predicted_verdict": predicted,
                "correct": correct,
                "missing_required_tools": sorted(required_tools - called_tool_set),
                "invalid_tool_calls": [
                    tool for tool in called_tools if allowed_tools and tool not in allowed_tools
                ],
                "missing_required_evidence": sorted(
                    set(required_evidence) - set(found_evidence)
                ),
            }
        )

    precision = _safe_div(true_positive, predicted_positive)
    recall = _safe_div(true_positive, actual_positive)
    metrics = {
        "run_name": run_name,
        "dataset_name": labels.get("name", ""),
        "dataset_version": labels.get("version", 1),
        "cases_total": len(cases),
        "pending_cases": len(all_cases) - len(cases),
        "matched_cases": matched,
        "missing_cases": len(cases) - matched,
        "extra_findings": len(findings) - len(used_findings),
        "verdict_accuracy": _safe_div(verdict_correct, len(cases)),
        "tp_precision": precision,
        "tp_recall": recall,
        "tp_f1": _safe_div(2 * precision * recall, precision + recall),
        "uncertain_rate": _safe_div(
            sum(1 for item in case_results if item.get("predicted_verdict") == "UNCERTAIN"),
            len(cases),
        ),
        "required_tool_recall": _safe_div(required_tools_found, required_tools_total),
        "useful_tool_call_rate": _safe_div(useful_tool_calls, total_tool_calls),
        "invalid_tool_call_rate": _safe_div(
            total_tool_calls - useful_tool_calls, total_tool_calls
        ),
        "required_evidence_recall": _safe_div(
            required_evidence_found, required_evidence_total
        ),
        "structured_output_success_rate": _safe_div(structured_successes, matched),
        "controlled_workflow_rate": _safe_div(workflow_cases, matched),
        "budget_exhaustion_rate": _safe_div(budget_exhaustions, workflow_cases),
        "critic_execution_rate": _safe_div(critic_executions, workflow_cases),
        "critic_rejection_rate": _safe_div(critic_rejections, critic_executions),
        "evidence_verified_rate": _safe_div(evidence_verified, matched),
        "fallback_usage_rate": _safe_div(fallback_uses, matched),
        "average_schema_rejections": _safe_div(schema_rejections, matched),
        "checkpoint_resume_rate": _safe_div(checkpoint_resumes, matched),
        "average_agent_steps": _safe_div(total_steps, matched),
        "average_tokens": _safe_div(total_tokens, matched),
        "average_latency_seconds": _safe_div(total_latency, matched),
        "total_tokens": total_tokens,
        "estimated_cost": total_tokens * price_per_million_tokens / 1_000_000,
        "by_defect": {
            key: {
                "cases": value["total"],
                "accuracy": _safe_div(value["correct"], value["total"]),
            }
            for key, value in sorted(by_defect.items())
        },
        "confusion_matrix": {
            f"{expected}->{predicted}": count
            for (expected, predicted), count in sorted(confusion.items())
        },
        "case_results": case_results,
    }
    return _round_metrics(metrics)


def comparison_rows(results: Iterable[Dict]) -> List[Dict]:
    keys = [
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
    return [
        {"run_name": result.get("run_name", ""), **{key: result.get(key, 0) for key in keys}}
        for result in results
    ]
