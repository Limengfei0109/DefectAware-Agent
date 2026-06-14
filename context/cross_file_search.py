import os
import re
from typing import Dict, List, Optional
import clang.cindex as cindex
from .compilation_database import CompilationDatabase


class CrossFileSearcher:
    """
    跨文件搜索器：在项目目录内搜索调用者、符号定义等。
    """

    DEFAULT_EXTENSIONS = {".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".hxx"}
    SOURCE_EXTENSIONS = {".cpp", ".cc", ".cxx", ".c"}

    def __init__(self, compilation_db: CompilationDatabase = None):
        self._index = cindex.Index.create()
        self.compilation_db = compilation_db

    # ----------------------------------------------------------------
    # 1. 跨文件调用者搜索
    # ----------------------------------------------------------------
    def find_callers(
        self,
        function_name: str,
        search_dir: str,
        compile_args: List[str] = None,
        max_files: int = 50,
    ) -> Dict[str, List[str]]:
        """
        在 search_dir 下递归扫描所有源文件，返回调用了 function_name 的
        {文件路径: [调用者函数名, ...]}。
        """
        compile_args = compile_args or ["-std=c++17"]
        results: Dict[str, List[str]] = {}
        scanned = 0

        for fpath in self._iter_files(search_dir, self.SOURCE_EXTENSIONS):
            if scanned >= max_files:
                break
            scanned += 1
            file_args = self.compilation_db.args_for(fpath) if self.compilation_db else compile_args
            callers = self._find_callers_in_file(fpath, function_name, file_args)
            if callers:
                results[fpath] = callers

        return results

    def _find_callers_in_file(
        self, file_path: str, target: str, compile_args: List[str]
    ) -> List[str]:
        try:
            tu = self._index.parse(file_path, args=compile_args)
        except Exception:
            return []
        callers: List[str] = []
        self._walk_for_callers(tu.cursor, file_path, target, None, callers)
        return callers

    def _walk_for_callers(self, cursor, file_path, target, current_func, callers):
        if cursor.kind in (
            cindex.CursorKind.FUNCTION_DECL,
            cindex.CursorKind.CXX_METHOD,
            cindex.CursorKind.CONSTRUCTOR,
            cindex.CursorKind.DESTRUCTOR,
            cindex.CursorKind.FUNCTION_TEMPLATE,
        ) and cursor.is_definition():
            loc = cursor.location
            if loc.file and os.path.normpath(loc.file.name) == os.path.normpath(file_path):
                current_func = cursor.spelling

        elif cursor.kind == cindex.CursorKind.CALL_EXPR and current_func:
            if cursor.spelling == target and current_func not in callers:
                callers.append(current_func)

        for child in cursor.get_children():
            self._walk_for_callers(child, file_path, target, current_func, callers)

    # ----------------------------------------------------------------
    # 2. 全局符号搜索
    # ----------------------------------------------------------------
    SYMBOL_KIND_MAP = {
        "macro": {cindex.CursorKind.MACRO_DEFINITION},
        "type": {
            cindex.CursorKind.CLASS_DECL,
            cindex.CursorKind.STRUCT_DECL,
            cindex.CursorKind.TYPEDEF_DECL,
            cindex.CursorKind.ENUM_DECL,
            cindex.CursorKind.TYPE_ALIAS_DECL,
        },
        "variable": {cindex.CursorKind.VAR_DECL},
        "function": {
            cindex.CursorKind.FUNCTION_DECL,
            cindex.CursorKind.CXX_METHOD,
            cindex.CursorKind.FUNCTION_TEMPLATE,
        },
    }

    def search_symbol(
        self,
        symbol_name: str,
        search_dir: str,
        compile_args: List[str] = None,
        symbol_type: str = "any",
        max_files: int = 50,
    ) -> List[dict]:
        """
        在 search_dir 下搜索 symbol_name 的定义/声明。
        返回 [{file, line, kind, snippet}, ...]
        """
        compile_args = compile_args or ["-std=c++17"]
        # 构建允许的 cursor kind 集合
        if symbol_type == "any":
            allowed = set()
            for kinds in self.SYMBOL_KIND_MAP.values():
                allowed |= kinds
        else:
            allowed = self.SYMBOL_KIND_MAP.get(symbol_type, set())
            if not allowed:
                allowed = set()
                for kinds in self.SYMBOL_KIND_MAP.values():
                    allowed |= kinds

        results: List[dict] = []
        scanned = 0

        for fpath in self._iter_files(search_dir, self.DEFAULT_EXTENSIONS):
            if scanned >= max_files:
                break
            scanned += 1
            # AST 搜索
            try:
                # 对于宏搜索需要 options=0x01 (详细预处理)
                opts = cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
                file_args = self.compilation_db.args_for(fpath) if self.compilation_db else compile_args
                tu = self._index.parse(fpath, args=file_args, options=opts)
            except Exception:
                continue

            for cursor in tu.cursor.walk_preorder():
                if cursor.kind not in allowed:
                    continue
                if cursor.spelling != symbol_name:
                    continue
                loc = cursor.location
                if loc.file is None:
                    continue
                results.append({
                    "file": loc.file.name,
                    "line": loc.line,
                    "kind": cursor.kind.name,
                    "snippet": self._read_snippet(loc.file.name, loc.line),
                })

        # 兜底：如果 AST 搜索无结果，用 grep 方式搜索
        if not results:
            results = self._grep_symbol(symbol_name, search_dir, symbol_type, max_files)

        return results

    # ----------------------------------------------------------------
    # 辅助方法
    # ----------------------------------------------------------------
    def _iter_files(self, search_dir: str, extensions: set):
        """递归遍历目录，yield 匹配扩展名的文件路径"""
        skip = {"build", "dist", "third_party", ".git", "__pycache__"}
        for root, dirs, files in os.walk(search_dir):
            dirs[:] = [d for d in dirs if d not in skip]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext in extensions:
                    yield os.path.join(root, fname)

    def _read_snippet(self, file_path: str, line: int, ctx: int = 2) -> str:
        """读取 line 前后 ctx 行作为代码片段"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            start = max(0, line - 1 - ctx)
            end = min(len(lines), line + ctx)
            return "".join(lines[start:end]).rstrip()
        except OSError:
            return ""

    def _grep_symbol(
        self, symbol_name: str, search_dir: str, symbol_type: str, max_files: int
    ) -> List[dict]:
        """正则兜底搜索：#define / typedef / class / struct / enum"""
        patterns = [
            re.compile(rf"#\s*define\s+{re.escape(symbol_name)}\b"),
            re.compile(rf"\btypedef\b.*\b{re.escape(symbol_name)}\s*;"),
            re.compile(rf"\b(?:class|struct|enum)\s+{re.escape(symbol_name)}\b"),
            re.compile(rf"\b{re.escape(symbol_name)}\s*\("),  # function decl
        ]
        results: List[dict] = []
        scanned = 0
        for fpath in self._iter_files(search_dir, self.DEFAULT_EXTENSIONS):
            if scanned >= max_files:
                break
            scanned += 1
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    for i, line in enumerate(f, 1):
                        for pat in patterns:
                            if pat.search(line):
                                results.append({
                                    "file": fpath,
                                    "line": i,
                                    "kind": "grep_match",
                                    "snippet": line.rstrip(),
                                })
                                break
            except OSError:
                continue
        return results
