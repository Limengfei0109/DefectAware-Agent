from typing import List
from models.finding import RawFinding, EnrichedFinding
from .function_extractor import FunctionExtractor
from .call_graph import CallGraphBuilder
from .data_flow import DataFlowTracer
from .libclang_config import configure_libclang
from .compilation_database import CompilationDatabase


class ContextBuilder:
    """
    为每个 RawFinding 提取代码上下文，生成 EnrichedFinding。
    """

    def __init__(self, libclang_path: str = "", compile_args: List[str] = None):
        self.compile_args = compile_args or ["-std=c++17"]
        self.compilation_db = CompilationDatabase(default_args=self.compile_args)
        configure_libclang(libclang_path)
        self.extractor = FunctionExtractor()
        self.call_graph = CallGraphBuilder()
        self.data_flow = DataFlowTracer()

    def configure_compile_commands(self, compile_commands: str = ""):
        self.compilation_db.load(compile_commands)

    def enrich(self, finding: RawFinding) -> EnrichedFinding:
        enriched = EnrichedFinding(raw=finding)
        compile_args = self.compilation_db.args_for(finding.file_path)

        # 1. 提取包含缺陷行的函数
        func_name, func_source, start, end = self.extractor.extract_function(
            finding.file_path, finding.line, compile_args
        )
        enriched.function_name = func_name
        enriched.function_source = func_source

        # 2. 提取缺陷行周围的原始上下文（±5 行）
        enriched.surrounding_context = self.extractor._read_lines(
            finding.file_path,
            max(1, finding.line - 5),
            finding.line + 5,
        )

        if func_name:
            # 3. 调用图
            enriched.callers = self.call_graph.get_callers(
                finding.file_path, func_name, compile_args
            )
            enriched.callees = self.call_graph.get_callees(
                finding.file_path, func_name, compile_args
            )

            # 4. 从报告 message 中提取变量名，做数据流分析
            var_name = self._extract_variable_from_message(finding.message)
            if var_name and func_source:
                enriched.variable_definitions = self.data_flow.find_variable_definitions(
                    func_source, var_name
                )

        # 5. 其他工具的佐证信息
        enriched.corroborating_tools = finding.extra.get("corroborating_tools", [])

        return enriched

    def enrich_batch(self, findings: List[RawFinding]) -> List[EnrichedFinding]:
        return [self.enrich(f) for f in findings]

    def _extract_variable_from_message(self, message: str) -> str:
        """从错误信息中提取被引用的变量名（启发式）"""
        import re
        # 匹配单引号或双引号中的标识符（大多数工具用引号括住变量名）
        m = re.search(r"['\"](\w+)['\"]", message)
        if m:
            return m.group(1)
        # 匹配 "variable 'xxx'" 或 "pointer 'xxx'" 模式
        m = re.search(r"(?:variable|pointer|value|member)\s+'?(\w+)'?", message)
        if m:
            return m.group(1)
        return ""
