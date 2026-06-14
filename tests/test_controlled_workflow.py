import unittest

from agent.workflow import CWERouter, ControlledVerificationWorkflow
from agent.evidence_verifier import EvidenceVerifier
from models.finding import EnrichedFinding, RawFinding


def _finding(defect_id="core.NullDereference", cwe="CWE-476"):
    return EnrichedFinding(
        raw=RawFinding(
            tool="clang-sa",
            file_path="sample.cpp",
            line=10,
            column=3,
            severity="warning",
            defect_id=defect_id,
            cwe=cwe,
            message="possible defect",
        ),
        function_name="sample",
        function_source="void sample(int *p) { *p = 1; }",
    )


class FakeToolExecutor:
    def __init__(self):
        self.calls = []

    def configure_environment(self, project_root, compile_commands=""):
        pass

    def execute(self, name, args):
        self.calls.append((name, args))
        return "L10 dereferences p without a preceding null check"


class FakeLLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.tool_sets = []

    def chat(self, messages, tools=None):
        self.tool_sets.append([item["name"] for item in tools or []])
        return self.responses.pop(0)

    def tool_result_messages(self, tool_results):
        return [
            {"role": "tool", "tool_call_id": item["id"], "content": item["content"]}
            for item in tool_results
        ]


def _response(tool_name, args, tokens=10):
    return {
        "content": "",
        "assistant_message": {"role": "assistant", "content": ""},
        "tool_calls": [{"id": tool_name, "name": tool_name, "args": args}],
        "tokens_used": tokens,
    }


def _workflow(responses, token_budget=1000, critic_enabled=True):
    workflow = ControlledVerificationWorkflow.__new__(ControlledVerificationWorkflow)
    workflow.llm = FakeLLM(responses)
    workflow.tool_executor = FakeToolExecutor()
    workflow.router = CWERouter()
    workflow.max_tool_calls = 3
    workflow.max_investigator_steps = 3
    workflow.token_budget = token_budget
    workflow.confidence_threshold = 0.7
    workflow.critic_enabled = critic_enabled
    workflow.structured_retries = 2
    workflow.evidence_verifier = EvidenceVerifier()
    return workflow


class ControlledWorkflowTests(unittest.TestCase):
    def test_router_constrains_tools_by_cwe(self):
        route = CWERouter().route(_finding("core.DivideZero", "CWE-369"))

        self.assertEqual("divide_by_zero", route.category)
        self.assertIn("find_variable_definition", route.allowed_tools)
        self.assertNotIn("search_null_checks", route.allowed_tools)

    def test_runs_investigator_verifier_and_critic(self):
        workflow = _workflow(
            [
                _response(
                    "get_function_context",
                    {"file_path": "sample.cpp", "function_name": "sample"},
                ),
                _response(
                    "submit_evidence",
                    {
                        "summary": ["p is dereferenced without a null check"],
                        "gaps": [],
                    },
                ),
                _response(
                    "submit_verdict",
                    {
                        "verdict": "TRUE_POSITIVE",
                        "confidence": 0.95,
                        "reasoning": ["L10 dereferences p without a preceding null check"],
                        "fixed_code": "if (p) { *p = 1; }",
                        "fix_explanation": "Guard the dereference.",
                    },
                ),
                _response("submit_critique", {"supported": True, "issues": []}),
            ]
        )

        result = workflow.verify(_finding())

        self.assertEqual("TRUE_POSITIVE", result.verdict)
        self.assertEqual("controlled_workflow", result.workflow_mode)
        self.assertEqual("null_dereference", result.workflow_route)
        self.assertFalse(result.budget_exhausted)
        self.assertTrue(result.structured_output_success)
        self.assertEqual(1, len(result.tool_calls_log))
        self.assertCountEqual(
            ["get_source_code", "get_function_context", "find_variable_definition",
             "search_null_checks", "get_callees", "get_callers_cross_file",
             "submit_evidence"],
            workflow.llm.tool_sets[0],
        )

    def test_critic_downgrades_unsupported_verdict(self):
        workflow = _workflow(
            [
                _response("submit_evidence", {"summary": [], "gaps": ["nullability unknown"]}),
                _response(
                    "submit_verdict",
                    {
                        "verdict": "FALSE_POSITIVE",
                        "confidence": 0.9,
                        "reasoning": ["assumed caller validates p"],
                    },
                ),
                _response(
                    "submit_critique",
                    {"supported": False, "issues": ["No caller evidence was collected."]},
                ),
            ]
        )

        result = workflow.verify(_finding())

        self.assertEqual("UNCERTAIN", result.verdict)
        self.assertLessEqual(result.confidence, 0.5)
        self.assertIn("Critic: No caller evidence was collected.", result.reasoning_chain)

    def test_token_budget_forces_uncertain_before_verdict(self):
        workflow = _workflow(
            [
                _response(
                    "submit_evidence",
                    {"summary": ["weak evidence"], "gaps": []},
                    tokens=100,
                )
            ],
            token_budget=50,
        )

        result = workflow.verify(_finding())

        self.assertEqual("UNCERTAIN", result.verdict)
        self.assertTrue(result.budget_exhausted)
        self.assertEqual(1, result.agent_steps)

    def test_invalid_structured_verdict_is_retried(self):
        workflow = _workflow(
            [
                _response(
                    "get_function_context",
                    {"file_path": "sample.cpp", "function_name": "sample"},
                ),
                _response("submit_evidence", {"summary": ["L10 dereferences p"], "gaps": []}),
                _response(
                    "submit_verdict",
                    {"verdict": "NOT_A_VERDICT", "confidence": 2, "reasoning": "bad"},
                ),
                _response(
                    "submit_verdict",
                    {
                        "verdict": "TRUE_POSITIVE",
                        "confidence": 0.9,
                        "reasoning": ["L10 dereferences p without a null check"],
                    },
                ),
                _response("submit_critique", {"supported": True, "issues": []}),
            ]
        )

        result = workflow.verify(_finding())

        self.assertEqual("TRUE_POSITIVE", result.verdict)
        self.assertEqual(1, result.schema_rejections)
        self.assertTrue(
            any(event["stage"] == "schema_rejected" for event in result.workflow_trace)
        )


if __name__ == "__main__":
    unittest.main()
