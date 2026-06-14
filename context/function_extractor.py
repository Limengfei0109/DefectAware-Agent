import os
from typing import Optional, List, Tuple
import clang.cindex as cindex


class FunctionExtractor:
    """
    基于 libclang 提取 C/C++ 函数定义。
    复用 AgentVisualizer 中的核心思路，针对新项目精简接口。
    """

    def __init__(self):
        self._index = cindex.Index.create()

    def extract_function(
        self,
        file_path: str,
        target_line: int,
        compile_args: List[str] = None,
    ) -> Tuple[str, str, int, int]:
        """
        提取包含 target_line 的函数。
        返回 (function_name, function_source, start_line, end_line)。
        若未找到则返回 ("", surrounding_context, target_line, target_line)。
        """
        compile_args = compile_args or ["-std=c++17"]
        try:
            tu = self._index.parse(file_path, args=compile_args)
        except Exception:
            # libclang 解析失败，降级为纯文本上下文
            context = self._read_lines(file_path, max(1, target_line - 10), target_line + 10)
            return "", context, target_line, target_line

        best = None
        for cursor in tu.cursor.walk_preorder():
            if cursor.kind not in (
                cindex.CursorKind.FUNCTION_DECL,
                cindex.CursorKind.CXX_METHOD,
                cindex.CursorKind.CONSTRUCTOR,
                cindex.CursorKind.DESTRUCTOR,
                cindex.CursorKind.FUNCTION_TEMPLATE,
            ):
                continue
            if not cursor.is_definition():
                continue
            if cursor.location.file is None:
                continue
            if os.path.normcase(os.path.realpath(cursor.location.file.name)) != (
                os.path.normcase(os.path.realpath(file_path))
            ):
                continue

            start = cursor.extent.start.line
            end = cursor.extent.end.line
            if start <= target_line <= end:
                # 找最小包含范围（最内层函数）
                if best is None or (end - start) < (best[2] - best[1]):
                    best = (cursor.spelling, start, end)

        if best:
            name, start, end = best
            source = self._read_lines(file_path, start, end)
            return name, source, start, end

        # 降级：返回前后 10 行作为上下文
        context = self._read_lines(file_path, max(1, target_line - 10), target_line + 10)
        return "", context, target_line, target_line

    def _read_lines(self, file_path: str, start: int, end: int) -> str:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            return "".join(lines[start - 1:end])
        except OSError:
            return ""
