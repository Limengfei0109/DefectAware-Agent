import json
import os
import plistlib
import tempfile
import unittest

from context.compilation_database import CompilationDatabase
from models.finding import EnrichedFinding, PathEvent, RawFinding
from models.report import AnalyzerFailure, DefectReport, FinalReport
from pipeline.report_generator import ReportGenerator


class CompilationDatabaseTests(unittest.TestCase):
    def test_returns_sanitized_per_file_arguments(self):
        with tempfile.TemporaryDirectory() as root:
            src = os.path.join(root, "src")
            inc = os.path.join(root, "include")
            os.makedirs(src)
            os.makedirs(inc)
            source = os.path.join(src, "main.cpp")
            open(source, "w", encoding="utf-8").close()
            database_path = os.path.join(root, "compile_commands.json")
            with open(database_path, "w", encoding="utf-8") as f:
                json.dump(
                    [
                        {
                            "directory": root,
                            "arguments": [
                                "clang++", "-Iinclude", "-DDEBUG", "-c",
                                "src/main.cpp", "-o", "main.o",
                            ],
                            "file": "src/main.cpp",
                        }
                    ],
                    f,
                )

            database = CompilationDatabase(database_path, ["-std=c++17"])
            args = database.args_for(source)

            self.assertIn("-DDEBUG", args)
            self.assertIn("-I" + os.path.realpath(inc), args)
            self.assertNotIn("-c", args)
            self.assertNotIn("main.o", args)
            self.assertNotIn("src/main.cpp", args)

    def test_bundled_libclang_can_be_configured(self):
        from context.libclang_config import configure_libclang
        import clang.cindex as cindex

        configure_libclang("")
        index = cindex.Index.create()
        self.assertIsNotNone(index)


class ReportGeneratorTests(unittest.TestCase):
    def test_html_escapes_content_and_json_restores_failures(self):
        raw = RawFinding(
            tool="clang-sa",
            file_path="sample.cpp",
            line=4,
            column=2,
            severity="error",
            defect_id="core.NullDereference",
            message="<script>alert(1)</script>",
            path_events=[
                PathEvent(file_path="sample.cpp", line=2, message="<b>null</b>")
            ],
        )
        report = FinalReport(
            project_path="<project>",
            total_raw_findings=1,
            total_analyzed=1,
            true_positives=1,
            false_positives=0,
            uncertain=0,
            false_positive_rate=0.0,
            reports=[
                DefectReport(
                    finding=EnrichedFinding(raw=raw),
                    verdict="TRUE_POSITIVE",
                    confidence=0.9,
                    reasoning_chain=["<img src=x onerror=alert(1)>"],
                    fixed_code="<unsafe>",
                )
            ],
            analyzer_failures=[
                AnalyzerFailure(
                    analyzer="ClangStaticAnalyzer",
                    file_path="bad.cpp",
                    error_category="missing-header",
                    error_summary="<missing>",
                )
            ],
            analyzer_failure_stats={"ClangStaticAnalyzer": 1},
        )

        with tempfile.TemporaryDirectory() as root:
            paths = ReportGenerator(root).generate(report, ["json", "html"])
            json_path = next(path for path in paths if path.endswith(".json"))
            html_path = next(path for path in paths if path.endswith(".html"))
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            with open(html_path, "r", encoding="utf-8") as f:
                page = f.read()

            self.assertEqual(1, data["summary"]["analyzer_failure_count"])
            self.assertEqual(1, len(data["analysis_failures"]))
            self.assertEqual(1, len(data["findings"][0]["path_events"]))
            self.assertIn("tool_calls_log", data["findings"][0])
            self.assertIn("agent_steps", data["findings"][0])
            self.assertIn("structured_output_success", data["findings"][0])
            self.assertIn("workflow_trace", data["findings"][0])
            self.assertIn("budget_exhausted", data["findings"][0])
            self.assertNotIn("<script>alert(1)</script>", page)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
            self.assertIn("分析失败", page)


class PlistPathTests(unittest.TestCase):
    def test_clang_plist_path_events_are_preserved(self):
        try:
            from analyzers.clang_static_analyzer import ClangStaticAnalyzer
        except ImportError:
            self.skipTest("optional clang Python bindings are not installed")

        payload = {
            "files": ["sample.cpp"],
            "diagnostics": [
                {
                    "check_name": "core.NullDereference",
                    "description": "null dereference",
                    "category": "Logic error",
                    "location": {"file": 0, "line": 9, "col": 3},
                    "path": [
                        {
                            "kind": "event",
                            "location": {"file": 0, "line": 4, "col": 7},
                            "extended_message": "Pointer is null",
                        }
                    ],
                }
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".plist", delete=False) as tmp:
            plistlib.dump(payload, tmp)
            path = tmp.name
        try:
            diagnostics = ClangStaticAnalyzer._load_plist(path)
        finally:
            os.unlink(path)
        self.assertEqual("Pointer is null", diagnostics[0]["path_events"][0]["message"])


class AgentProtocolTests(unittest.TestCase):
    def test_provider_native_tool_results(self):
        from agent.llm_client import LLMClient

        client = LLMClient({"provider": "local"})
        openai_messages = client.tool_result_messages(
            [{"id": "call-1", "content": "result"}]
        )
        self.assertEqual("tool", openai_messages[0]["role"])
        self.assertEqual("call-1", openai_messages[0]["tool_call_id"])

        client.provider = "claude"
        claude_messages = client.tool_result_messages(
            [{"id": "call-2", "content": "result"}]
        )
        block = claude_messages[0]["content"][0]
        self.assertEqual("tool_result", block["type"])
        self.assertEqual("call-2", block["tool_use_id"])

    def test_agent_accepts_structured_submit_verdict(self):
        from agent.agent import DefectVerificationAgent

        class FakeLLM:
            def chat(self, messages, tools=None):
                return {
                    "content": "",
                    "assistant_message": {"role": "assistant", "content": ""},
                    "tool_calls": [
                        {
                            "id": "final-1",
                            "name": "submit_verdict",
                            "args": {
                                "verdict": "TRUE_POSITIVE",
                                "confidence": 0.95,
                                "reasoning": ["path event proves null dereference"],
                            },
                        }
                    ],
                    "tokens_used": 4,
                }

        agent = DefectVerificationAgent.__new__(DefectVerificationAgent)
        agent.llm = FakeLLM()
        agent.max_steps = 1
        agent.confidence_threshold = 0.7
        raw = RawFinding(
            tool="clang-sa",
            file_path="sample.cpp",
            line=1,
            column=1,
            severity="error",
            defect_id="core.NullDereference",
            message="null",
        )
        result = agent.verify(EnrichedFinding(raw=raw))
        self.assertEqual("TRUE_POSITIVE", result.verdict)
        self.assertEqual(0.95, result.confidence)
        self.assertEqual(1, result.agent_steps)
        self.assertTrue(result.structured_output_success)

    def test_direct_llm_ablation_exposes_only_final_verdict_tool(self):
        from agent.agent import DefectVerificationAgent

        class FakeLLM:
            def __init__(self):
                self.tools = None

            def chat(self, messages, tools=None):
                self.tools = tools
                return {
                    "content": "",
                    "assistant_message": {"role": "assistant", "content": ""},
                    "tool_calls": [
                        {
                            "id": "final-1",
                            "name": "submit_verdict",
                            "args": {
                                "verdict": "UNCERTAIN",
                                "confidence": 0.5,
                                "reasoning": ["finding alone is insufficient"],
                            },
                        }
                    ],
                    "tokens_used": 3,
                }

        agent = DefectVerificationAgent.__new__(DefectVerificationAgent)
        agent.llm = FakeLLM()
        agent.max_steps = 1
        agent.confidence_threshold = 0.7
        agent.mode = "direct_llm"
        raw = RawFinding(
            tool="clang-sa",
            file_path="sample.cpp",
            line=1,
            column=1,
            severity="error",
            defect_id="core.NullDereference",
            message="null",
        )

        agent.verify(EnrichedFinding(raw=raw, function_source="secret context"))

        self.assertEqual(["submit_verdict"], [tool["name"] for tool in agent.llm.tools])

    def test_tool_paths_cannot_escape_project_root(self):
        from agent.tools import ToolExecutor

        with tempfile.TemporaryDirectory() as root:
            executor = ToolExecutor.__new__(ToolExecutor)
            executor.project_root = os.path.realpath(root)
            inside = os.path.join(root, "source.cpp")
            open(inside, "w", encoding="utf-8").close()
            self.assertEqual(os.path.realpath(inside), executor._safe_path(inside))
            with self.assertRaises(ValueError):
                executor._safe_path(os.path.join(root, "..", "outside.cpp"), must_exist=False)


if __name__ == "__main__":
    unittest.main()
