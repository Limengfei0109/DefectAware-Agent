import os
import tempfile
import unittest

from models.finding import EnrichedFinding, RawFinding
from models.report import DefectReport, FinalReport
from observability.trace_store import TraceStore
from observability.integration import record_report_if_enabled


def _report():
    finding = EnrichedFinding(
        raw=RawFinding(
            tool="clang-sa",
            file_path="sample.cpp",
            line=7,
            column=2,
            severity="warning",
            defect_id="core.NullDereference",
            cwe="CWE-476",
            message="possible null dereference",
        )
    )
    defect = DefectReport(
        finding=finding,
        verdict="UNCERTAIN",
        confidence=0.5,
        reasoning_chain=["Critic rejected unsupported conclusion."],
        tool_calls_log=[
            {
                "tool": "get_function_context",
                "args": {"file_path": "sample.cpp", "function_name": "sample"},
                "observation": "source",
            }
        ],
        processing_time=1.5,
        llm_tokens_used=100,
        agent_steps=3,
        structured_output_success=True,
        workflow_mode="controlled_workflow",
        workflow_route="null_dereference",
        workflow_trace=[
            {
                "stage": "verifier",
                "detail": {
                    "prompt": "judge evidence",
                    "tokens_used": 40,
                    "latency_seconds": 0.5,
                },
            }
        ],
    )
    return FinalReport(
        project_path="project",
        total_raw_findings=1,
        total_analyzed=1,
        true_positives=0,
        false_positives=0,
        uncertain=1,
        false_positive_rate=0.0,
        reports=[defect],
        generated_at="2026-06-14T00:00:00Z",
    )


class TraceStoreTests(unittest.TestCase):
    def test_records_run_findings_events_tools_and_evaluation(self):
        with tempfile.TemporaryDirectory() as root:
            store = TraceStore(os.path.join(root, "traces.db"))
            run_id = store.record_report(
                _report(),
                {
                    "provider": "local",
                    "model": "test-model",
                    "agent_mode": "controlled_workflow",
                },
            )
            store.import_evaluation(
                run_id,
                {
                    "verdict_accuracy": 0.8,
                    "by_defect": {"core.NullDereference": {"cases": 1, "accuracy": 0.8}},
                },
            )

            runs = store.query("SELECT * FROM runs")
            findings = store.query("SELECT * FROM findings")
            events = store.query("SELECT * FROM events")
            tools = store.query("SELECT * FROM tool_calls")
            evaluations = store.query("SELECT * FROM evaluations")

            self.assertEqual(run_id, runs[0]["run_id"])
            self.assertEqual("test-model", runs[0]["model"])
            self.assertEqual("UNCERTAIN", findings[0]["verdict"])
            self.assertEqual("judge evidence", events[0]["prompt"])
            self.assertEqual("get_function_context", tools[0]["tool_name"])
            self.assertEqual(1, tools[0]["success"])
            self.assertEqual(1, len(evaluations))

    def test_rejects_evaluation_for_unknown_run(self):
        with tempfile.TemporaryDirectory() as root:
            store = TraceStore(os.path.join(root, "traces.db"))
            with self.assertRaises(ValueError):
                store.import_evaluation("missing", {})

    def test_integration_sets_report_run_id(self):
        with tempfile.TemporaryDirectory() as root:
            report = _report()
            run_id = record_report_if_enabled(
                report,
                {
                    "llm": {"provider": "local", "model": "test-model"},
                    "agent": {"mode": "controlled_workflow"},
                    "observability": {
                        "enabled": True,
                        "db_path": os.path.join(root, "traces.db"),
                    },
                },
            )

            self.assertEqual(run_id, report.run_id)
            self.assertTrue(run_id)


if __name__ == "__main__":
    unittest.main()
