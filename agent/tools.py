import json
import os
from typing import Dict, List

from context.compilation_database import CompilationDatabase
from .schema_validation import validate_tool_call


TOOL_SCHEMAS = [
    {
        "name": "get_source_code",
        "description": "Read a bounded line range from a source file inside the project.",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "start_line": {"type": "integer"},
                "end_line": {"type": "integer"},
            },
            "required": ["file_path", "start_line", "end_line"],
        },
    },
    {
        "name": "get_function_context",
        "description": "Get the complete definition of a function from a project source file.",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "function_name": {"type": "string"},
            },
            "required": ["file_path", "function_name"],
        },
    },
    {
        "name": "find_variable_definition",
        "description": "Find definitions, assignments, and null checks for a variable in a function.",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "function_name": {"type": "string"},
                "variable_name": {"type": "string"},
            },
            "required": ["file_path", "function_name", "variable_name"],
        },
    },
    {
        "name": "get_callers",
        "description": "Find functions in the same file that call the target function.",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "function_name": {"type": "string"},
            },
            "required": ["file_path", "function_name"],
        },
    },
    {
        "name": "get_callees",
        "description": "Find functions called by the target function.",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "function_name": {"type": "string"},
            },
            "required": ["file_path", "function_name"],
        },
    },
    {
        "name": "search_null_checks",
        "description": "Search for null checks involving a variable inside a function.",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "function_name": {"type": "string"},
                "variable_name": {"type": "string"},
                "start_line": {"type": "integer"},
                "end_line": {"type": "integer"},
            },
            "required": ["file_path", "function_name", "variable_name"],
        },
    },
    {
        "name": "get_callers_cross_file",
        "description": "Search project source files for callers of a function.",
        "parameters": {
            "type": "object",
            "properties": {
                "function_name": {"type": "string"},
                "search_dir": {"type": "string"},
                "max_files": {"type": "integer"},
            },
            "required": ["function_name", "search_dir"],
        },
    },
    {
        "name": "get_file_context",
        "description": "Read a bounded line range from any project source or header file.",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "start_line": {"type": "integer"},
                "end_line": {"type": "integer"},
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "search_symbol",
        "description": "Search the project for a macro, type, variable, or function symbol.",
        "parameters": {
            "type": "object",
            "properties": {
                "symbol_name": {"type": "string"},
                "search_dir": {"type": "string"},
                "symbol_type": {
                    "type": "string",
                    "enum": ["macro", "type", "variable", "function", "any"],
                },
            },
            "required": ["symbol_name", "search_dir"],
        },
    },
]

for _schema in TOOL_SCHEMAS:
    _schema["parameters"].setdefault("additionalProperties", False)

FINAL_VERDICT_TOOL = {
    "name": "submit_verdict",
    "description": "Submit the final structured defect verdict after collecting enough evidence.",
    "parameters": {
        "type": "object",
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN"],
            },
            "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            "reasoning": {"type": "array", "items": {"type": "string"}},
            "fixed_code": {"type": "string"},
            "fix_explanation": {"type": "string"},
        },
        "required": ["verdict", "confidence", "reasoning"],
        "additionalProperties": False,
    },
}


class ToolExecutor:
    """Execute bounded code-inspection tools for the verification agent."""

    def __init__(
        self,
        libclang_path: str = "",
        compile_args: List[str] = None,
        project_root: str = "",
        compile_commands: str = "",
        safety_config: Dict = None,
    ):
        safety_config = safety_config or {}
        self.compile_args = compile_args or ["-std=c++17"]
        self.project_root = ""
        self.cache_enabled = bool(safety_config.get("tool_cache_enabled", True))
        self.max_argument_length = max(64, int(safety_config.get("max_argument_length", 4096)))
        self._cache: Dict[str, str] = {}
        self.compilation_db = CompilationDatabase(compile_commands, self.compile_args)

        from context.libclang_config import configure_libclang
        from context.function_extractor import FunctionExtractor
        from context.call_graph import CallGraphBuilder
        from context.data_flow import DataFlowTracer
        from context.cross_file_search import CrossFileSearcher

        configure_libclang(libclang_path)
        self._extractor = FunctionExtractor()
        self._call_graph = CallGraphBuilder()
        self._data_flow = DataFlowTracer()
        self._cross_file = CrossFileSearcher(self.compilation_db)
        self.configure_environment(project_root, compile_commands)

    def configure_environment(self, project_root: str, compile_commands: str = ""):
        self.project_root = os.path.realpath(project_root) if project_root else ""
        self._cache.clear()
        self.compilation_db.load(compile_commands)

    def _safe_path(self, path: str, must_exist: bool = True) -> str:
        if not self.project_root:
            raise ValueError("project root is not configured")
        candidate = path if os.path.isabs(path) else os.path.join(self.project_root, path)
        candidate = os.path.realpath(candidate)
        try:
            inside = os.path.normcase(os.path.commonpath([candidate, self.project_root])) == (
                os.path.normcase(self.project_root)
            )
        except ValueError:
            inside = False
        if not inside:
            raise ValueError("path is outside the project root")
        if must_exist and not os.path.exists(candidate):
            raise ValueError("path does not exist")
        return candidate

    def _args_for(self, file_path: str) -> List[str]:
        return self.compilation_db.args_for(file_path)

    def execute(self, tool_name: str, args: Dict) -> str:
        try:
            valid, errors = validate_tool_call(
                {"name": tool_name, "args": args}, TOOL_SCHEMAS
            )
            if not valid:
                return f"[Validation error] {tool_name}: {'; '.join(errors)}"
            for key, value in args.items():
                if isinstance(value, str) and len(value) > self.max_argument_length:
                    return f"[Validation error] {tool_name}: argument '{key}' is too long"
            cache_key = json.dumps([tool_name, args], ensure_ascii=False, sort_keys=True)
            if self.cache_enabled and cache_key in self._cache:
                return self._cache[cache_key]
            handler = getattr(self, f"_tool_{tool_name}", None)
            if handler is None:
                return f"[Error] Unknown tool: {tool_name}"
            result = handler(**args)
            if self.cache_enabled and not result.startswith(("[Error]", "[Tool error]")):
                self._cache[cache_key] = result
            return result
        except Exception as exc:
            return f"[Tool error] {tool_name}: {exc}"

    @staticmethod
    def _numbered(source: str, start_line: int) -> str:
        return "\n".join(
            f"{start_line + index:4d} | {line}"
            for index, line in enumerate(source.splitlines())
        )

    @staticmethod
    def _find_function_line(file_path: str, function_name: str) -> int:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line_number, line in enumerate(f, start=1):
                if function_name in line and "(" in line:
                    return line_number
        return 0

    def _tool_get_source_code(self, file_path: str, start_line: int, end_line: int) -> str:
        file_path = self._safe_path(file_path)
        start_line = max(1, int(start_line))
        end_line = min(max(start_line, int(end_line)), start_line + 500)
        source = self._extractor._read_lines(file_path, start_line, end_line)
        return (
            f"```cpp\n{self._numbered(source, start_line)}\n```"
            if source
            else f"[Unable to read] {file_path} L{start_line}-{end_line}"
        )

    def _tool_get_function_context(self, file_path: str, function_name: str) -> str:
        file_path = self._safe_path(file_path)
        start = self._find_function_line(file_path, function_name)
        if not start:
            return f"[Not found] Function '{function_name}' in {file_path}"
        _, source, begin, end = self._extractor.extract_function(
            file_path, start, self._args_for(file_path)
        )
        return (
            f"// {function_name} (L{begin}-{end})\n```cpp\n{source}\n```"
            if source
            else f"[Unable to extract] Function '{function_name}'"
        )

    def _tool_find_variable_definition(
        self, file_path: str, function_name: str, variable_name: str
    ) -> str:
        file_path = self._safe_path(file_path)
        start = self._find_function_line(file_path, function_name)
        if not start:
            return f"[Not found] Function '{function_name}'"
        _, source, begin, end = self._extractor.extract_function(
            file_path, start, self._args_for(file_path)
        )
        definitions = self._data_flow.find_variable_definitions(source, variable_name)
        if not definitions:
            return f"[Not found] No definition or assignment for '{variable_name}'"
        lines = "\n".join(f"- [{reason}] {code}" for code, reason in definitions.items())
        return f"// {function_name} L{begin}-{end}: '{variable_name}' evidence\n{lines}"

    def _tool_get_callers(self, file_path: str, function_name: str) -> str:
        file_path = self._safe_path(file_path)
        callers = self._call_graph.get_callers(file_path, function_name, self._args_for(file_path))
        return "\n".join(f"- {name}" for name in callers) or "[Not found] No same-file callers"

    def _tool_get_callees(self, file_path: str, function_name: str) -> str:
        file_path = self._safe_path(file_path)
        callees = self._call_graph.get_callees(file_path, function_name, self._args_for(file_path))
        return "\n".join(f"- {name}" for name in callees) or "[Not found] No callees"

    def _tool_search_null_checks(
        self,
        file_path: str,
        function_name: str,
        variable_name: str,
        start_line: int = 1,
        end_line: int = 9999,
    ) -> str:
        file_path = self._safe_path(file_path)
        function_line = self._find_function_line(file_path, function_name) or start_line
        _, source, begin, _ = self._extractor.extract_function(
            file_path, function_line, self._args_for(file_path)
        )
        found = self._data_flow.find_null_checks(
            source, variable_name, 1, max(1, int(end_line) - begin + 1)
        )
        return (
            f"[Found] Null check for '{variable_name}'"
            if found
            else f"[Not found] Null check for '{variable_name}'"
        )

    def _tool_get_callers_cross_file(
        self, function_name: str, search_dir: str, max_files: int = 50
    ) -> str:
        search_dir = self._safe_path(search_dir)
        max_files = max(1, min(int(max_files), 500))
        results = self._cross_file.find_callers(
            function_name, search_dir, self.compile_args, max_files
        )
        lines = [
            f"- {os.path.basename(path)}: {caller}()"
            for path, callers in results.items()
            for caller in callers
        ]
        return "\n".join(lines) or f"[Not found] No callers in the first {max_files} files"

    def _tool_get_file_context(
        self, file_path: str, start_line: int = 1, end_line: int = 0
    ) -> str:
        end_line = int(end_line) if end_line else int(start_line) + 199
        return self._tool_get_source_code(file_path, int(start_line), end_line)

    def _tool_search_symbol(
        self, symbol_name: str, search_dir: str, symbol_type: str = "any"
    ) -> str:
        search_dir = self._safe_path(search_dir)
        results = self._cross_file.search_symbol(
            symbol_name, search_dir, self.compile_args, symbol_type
        )
        lines = []
        seen = set()
        for result in results[:20]:
            key = (result["file"], result["line"])
            if key in seen:
                continue
            seen.add(key)
            lines.append(
                f"- {os.path.basename(result['file'])}:{result['line']} "
                f"[{result['kind']}]\n  {result['snippet']}"
            )
        return "\n".join(lines) or f"[Not found] Symbol '{symbol_name}'"
