import unittest

from evaluation.evaluator import comparison_rows, evaluate_report
from evaluation.dataset_builder import build_candidate_dataset


class EvaluationTests(unittest.TestCase):
    def test_calculates_verdict_tool_evidence_and_runtime_metrics(self):
        labels = {
            "name": "unit-test",
            "version": 1,
            "cases": [
                {
                    "id": "tp-case",
                    "match": {
                        "file_path": "src/sample.cpp",
                        "line": 8,
                        "defect_id": "core.NullDereference",
                    },
                    "expected_verdict": "TRUE_POSITIVE",
                    "required_tools": [
                        "get_function_context",
                        "find_variable_definition",
                    ],
                    "optional_tools": ["search_null_checks"],
                    "required_evidence": ["no null check", "dereference"],
                },
                {
                    "id": "fp-case",
                    "match": {
                        "file_path": "src/safe.cpp",
                        "line": 12,
                        "defect_id": "core.NullDereference",
                    },
                    "expected_verdict": "FALSE_POSITIVE",
                },
            ],
        }
        report = {
            "findings": [
                {
                    "file_path": "D:/repo/src/sample.cpp",
                    "line": 8,
                    "defect_id": "core.NullDereference",
                    "verdict": "TRUE_POSITIVE",
                    "reasoning_chain": ["The dereference is reachable."],
                    "tool_calls_log": [
                        {
                            "step": 0,
                            "tool": "get_function_context",
                            "observation": "There is no null check.",
                        },
                        {
                            "step": 1,
                            "tool": "search_symbol",
                            "observation": "irrelevant",
                        },
                    ],
                    "llm_tokens_used": 1000,
                    "processing_time": 4.0,
                    "agent_steps": 3,
                    "structured_output_success": True,
                },
                {
                    "file_path": "D:/repo/src/safe.cpp",
                    "line": 12,
                    "defect_id": "core.NullDereference",
                    "verdict": "TRUE_POSITIVE",
                    "reasoning_chain": [],
                    "tool_calls_log": [],
                    "llm_tokens_used": 500,
                    "processing_time": 2.0,
                    "agent_steps": 1,
                    "structured_output_success": False,
                },
            ]
        }

        result = evaluate_report(
            labels, report, run_name="react-tools", price_per_million_tokens=2.0
        )

        self.assertEqual(0.5, result["verdict_accuracy"])
        self.assertEqual(0.5, result["tp_precision"])
        self.assertEqual(1.0, result["tp_recall"])
        self.assertEqual(0.6667, result["tp_f1"])
        self.assertEqual(0.5, result["required_tool_recall"])
        self.assertEqual(0.5, result["useful_tool_call_rate"])
        self.assertEqual(0.5, result["invalid_tool_call_rate"])
        self.assertEqual(1.0, result["required_evidence_recall"])
        self.assertEqual(0.5, result["structured_output_success_rate"])
        self.assertEqual(2.0, result["average_agent_steps"])
        self.assertEqual(750.0, result["average_tokens"])
        self.assertEqual(3.0, result["average_latency_seconds"])
        self.assertEqual(0.003, result["estimated_cost"])
        self.assertEqual(["find_variable_definition"], result["case_results"][0]["missing_required_tools"])
        self.assertEqual(["search_symbol"], result["case_results"][0]["invalid_tool_calls"])

    def test_reports_missing_and_extra_findings(self):
        labels = {
            "cases": [
                {
                    "id": "missing",
                    "match": {"file_path": "missing.cpp", "line": 1},
                    "expected_verdict": "TRUE_POSITIVE",
                }
            ]
        }
        report = {
            "findings": [
                {
                    "file_path": "extra.cpp",
                    "line": 2,
                    "defect_id": "core.DivideZero",
                    "verdict": "TRUE_POSITIVE",
                }
            ]
        }

        result = evaluate_report(labels, report)

        self.assertEqual(0, result["matched_cases"])
        self.assertEqual(1, result["missing_cases"])
        self.assertEqual(1, result["extra_findings"])
        self.assertEqual(0.0, result["tp_recall"])

    def test_calculates_controlled_workflow_metrics(self):
        labels = {
            "cases": [
                {
                    "id": "workflow-case",
                    "match": {"file_path": "sample.cpp", "line": 1},
                    "expected_verdict": "UNCERTAIN",
                }
            ]
        }
        report = {
            "findings": [
                {
                    "file_path": "sample.cpp",
                    "line": 1,
                    "verdict": "UNCERTAIN",
                    "workflow_mode": "controlled_workflow",
                    "budget_exhausted": False,
                    "evidence_verified": True,
                    "fallback_used": True,
                    "schema_rejections": 2,
                    "resumed_from_checkpoint": True,
                    "workflow_trace": [
                        {
                            "stage": "critic_complete",
                            "detail": {"supported": False, "issues": ["unsupported"]},
                        }
                    ],
                }
            ]
        }

        result = evaluate_report(labels, report)

        self.assertEqual(1.0, result["controlled_workflow_rate"])
        self.assertEqual(0.0, result["budget_exhaustion_rate"])
        self.assertEqual(1.0, result["critic_execution_rate"])
        self.assertEqual(1.0, result["critic_rejection_rate"])
        self.assertEqual(1.0, result["evidence_verified_rate"])
        self.assertEqual(1.0, result["fallback_usage_rate"])
        self.assertEqual(2.0, result["average_schema_rejections"])
        self.assertEqual(1.0, result["checkpoint_resume_rate"])

    def test_builds_comparison_rows(self):
        rows = comparison_rows(
            [
                {"run_name": "baseline", "verdict_accuracy": 0.5},
                {"run_name": "react", "verdict_accuracy": 0.8},
            ]
        )

        self.assertEqual("baseline", rows[0]["run_name"])
        self.assertEqual(0.8, rows[1]["verdict_accuracy"])
        self.assertIn("average_tokens", rows[0])

    def test_pending_cases_are_not_used_as_ground_truth(self):
        labels = {
            "cases": [
                {
                    "id": "pending",
                    "review_status": "pending",
                    "match": {"file_path": "sample.cpp", "line": 1},
                    "expected_verdict": "",
                }
            ]
        }

        result = evaluate_report(labels, {"findings": []})

        self.assertEqual(0, result["cases_total"])
        self.assertEqual(1, result["pending_cases"])

    def test_candidate_builder_samples_across_defect_types(self):
        report = {
            "findings": [
                {
                    "file_path": "a.cpp",
                    "line": 1,
                    "defect_id": "core.NullDereference",
                    "verdict": "TRUE_POSITIVE",
                    "confidence": 0.9,
                },
                {
                    "file_path": "b.cpp",
                    "line": 2,
                    "defect_id": "core.NullDereference",
                    "verdict": "FALSE_POSITIVE",
                    "confidence": 0.8,
                },
                {
                    "file_path": "c.cpp",
                    "line": 3,
                    "defect_id": "core.DivideZero",
                    "verdict": "TRUE_POSITIVE",
                    "confidence": 0.7,
                },
            ]
        }

        dataset = build_candidate_dataset([report], "sample", limit=2)

        self.assertEqual(2, len(dataset["cases"]))
        self.assertEqual(
            {"core.NullDereference", "core.DivideZero"},
            {case["match"]["defect_id"] for case in dataset["cases"]},
        )
        self.assertTrue(all(case["review_status"] == "pending" for case in dataset["cases"]))


if __name__ == "__main__":
    unittest.main()
