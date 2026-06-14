import os
from typing import Dict, List, Tuple
import clang.cindex as cindex


class CallGraphBuilder:
    """
    基于 libclang AST 构建函数调用图。
    """

    def __init__(self):
        self._index = cindex.Index.create()
        # 缓存：file_path -> {func_name: [callee_name, ...]}
        self._cache: Dict[Tuple[str, Tuple[str, ...]], Dict[str, List[str]]] = {}

    def get_callees(self, file_path: str, function_name: str,
                    compile_args: List[str] = None) -> List[str]:
        """返回指定函数调用的所有函数名列表"""
        graph = self._build_for_file(file_path, compile_args)
        return graph.get(function_name, [])

    def get_callers(self, file_path: str, function_name: str,
                    compile_args: List[str] = None) -> List[str]:
        """返回调用指定函数的所有函数名列表（在同一文件内）"""
        graph = self._build_for_file(file_path, compile_args)
        return [caller for caller, callees in graph.items() if function_name in callees]

    def _build_for_file(self, file_path: str,
                        compile_args: List[str] = None) -> Dict[str, List[str]]:
        compile_args = compile_args or ["-std=c++17"]
        cache_key = (os.path.normcase(os.path.realpath(file_path)), tuple(compile_args))
        if cache_key in self._cache:
            return self._cache[cache_key]
        try:
            tu = self._index.parse(file_path, args=compile_args)
        except Exception:
            self._cache[cache_key] = {}
            return {}

        graph: Dict[str, List[str]] = {}
        self._visit(tu.cursor, file_path, None, graph)
        self._cache[cache_key] = graph
        return graph

    def _visit(self, cursor, file_path: str, current_func: str,
               graph: Dict[str, List[str]]):
        if cursor.kind in (
            cindex.CursorKind.FUNCTION_DECL,
            cindex.CursorKind.CXX_METHOD,
            cindex.CursorKind.CONSTRUCTOR,
            cindex.CursorKind.DESTRUCTOR,
            cindex.CursorKind.FUNCTION_TEMPLATE,
        ) and cursor.is_definition():
            if cursor.location.file and os.path.normcase(os.path.realpath(cursor.location.file.name)) == (
                os.path.normcase(os.path.realpath(file_path))
            ):
                current_func = cursor.spelling
                graph.setdefault(current_func, [])

        elif cursor.kind == cindex.CursorKind.CALL_EXPR and current_func:
            callee = cursor.spelling
            if callee and callee not in graph.get(current_func, []):
                graph.setdefault(current_func, []).append(callee)

        for child in cursor.get_children():
            self._visit(child, file_path, current_func, graph)
