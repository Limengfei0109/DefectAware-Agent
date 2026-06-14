import os
import tempfile
import unittest

from agent.evidence_verifier import EvidenceVerifier
from agent.llm_client import LLMClient
from agent.schema_validation import validate_schema
from agent.tools import ToolExecutor
from agent.verdict import VerdictResult
from models.finding import EnrichedFinding, RawFinding
from models.report import DefectReport
from pipeline.checkpoint import CheckpointStore


def _finding(path="sample.cpp"):
    return EnrichedFinding(
        raw=RawFinding(
            tool="clang-sa",
            file_path=path,
            line=2,
            column=1,
            severity="warning",
            defect_id="core.NullDereference",
            message="possible null dereference",
        )
    )


class ReliabilityTests(unittest.TestCase):
    def test_schema_validator_rejects_invalid_payload(self):
        schema = {
            "type": "object",
            "properties": {"verdict": {"type": "string", "enum": ["UNCERTAIN"]}},
            "required": ["verdict"],
            "additionalProperties": False,
        }

        errors = validate_schema({"verdict": "TRUE_POSITIVE", "extra": 1}, schema)

        self.assertEqual(2, len(errors))

    def test_tool_executor_rejects_invalid_args_and_caches_results(self):
        executor = ToolExecutor.__new__(ToolExecutor)
        executor.cache_enabled = True
        executor.max_argument_length = 4096
        executor._cache = {}
        calls = []

        def source(file_path, start_line, end_line):
            calls.append(file_path)
            return "source"

        executor._tool_get_source_code = source

        invalid = executor.execute("get_source_code", {"file_path": "sample.cpp"})
        first = executor.execute(
            "get_source_code",
            {"file_path": "sample.cpp", "start_line": 1, "end_line": 2},
        )
        second = executor.execute(
            "get_source_code",
            {"file_path": "sample.cpp", "start_line": 1, "end_line": 2},
        )

        self.assertTrue(invalid.startswith("[Validation error]"))
        self.assertEqual("source", first)
        self.assertEqual("source", second)
        self.assertEqual(["sample.cpp"], calls)

    def test_evidence_verifier_checks_line_citations(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "sample.cpp")
            with open(path, "w", encoding="utf-8") as file:
                file.write("int x = 0;\nreturn *ptr;\n")
            verifier = EvidenceVerifier()
            verifier.configure_environment(root)

            supported, issues = verifier.verify(
                _finding(path),
                VerdictResult(
                    verdict="TRUE_POSITIVE",
                    confidence=0.9,
                    reasoning=["sample.cpp:L2 dereferences ptr."],
                ),
                [],
            )
            missing, missing_issues = verifier.verify(
                _finding(path),
                VerdictResult(
                    verdict="TRUE_POSITIVE",
                    confidence=0.9,
                    reasoning=["The pointer is unsafe."],
                ),
                [],
            )
            unrelated, unrelated_issues = verifier.verify(
                _finding(path),
                VerdictResult(
                    verdict="TRUE_POSITIVE",
                    confidence=0.9,
                    reasoning=["sample.cpp:L2 contains a null check."],
                ),
                [],
            )

            self.assertTrue(supported)
            self.assertFalse(issues)
            self.assertFalse(missing)
            self.assertTrue(missing_issues)
            self.assertFalse(unrelated)
            self.assertTrue(unrelated_issues)

    def test_llm_fallback_is_used_after_primary_failure(self):
        class Fallback:
            model = "fallback-model"

            def chat(self, messages, tools=None):
                return {"content": "ok", "tool_calls": [], "tokens_used": 1}

        client = LLMClient.__new__(LLMClient)
        client.provider = "openai"
        client.fallback = Fallback()
        client._chat_openai_compat = lambda messages, tools: (_ for _ in ()).throw(
            RuntimeError("primary failed")
        )

        response = client.chat([])

        self.assertTrue(response["fallback_used"])
        self.assertEqual("fallback-model", response["fallback_model"])

    def test_checkpoint_is_namespaced_and_restores_report(self):
        with tempfile.TemporaryDirectory() as root:
            finding = _finding()
            report = DefectReport(finding=finding, verdict="UNCERTAIN", confidence=0.4)
            first = CheckpointStore(root, namespace="model-a")
            second = CheckpointStore(root, namespace="model-b")
            first.save(finding, first.report_payload(report))

            self.assertIsNotNone(first.load(finding))
            self.assertIsNone(second.load(finding))
            restored = first.restore_report(finding, first.load(finding))
            self.assertTrue(restored.resumed_from_checkpoint)

    def test_checkpoint_namespace_changes_with_agent_config(self):
        first = CheckpointStore.namespace_for(
            {"llm": {"model": "a", "api_key": "secret"}, "agent": {"mode": "one"}}
        )
        same_without_secret = CheckpointStore.namespace_for(
            {"llm": {"model": "a", "api_key": "different"}, "agent": {"mode": "one"}}
        )
        second = CheckpointStore.namespace_for(
            {"llm": {"model": "a"}, "agent": {"mode": "two"}}
        )

        self.assertEqual(first, same_without_secret)
        self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()
