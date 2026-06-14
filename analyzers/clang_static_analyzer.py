import json
import os
import plistlib
import shlex
import subprocess
import tempfile
try:
    import winreg  # type: ignore
except ImportError:  # non-Windows runners
    winreg = None
from typing import List, Optional

from .base import BaseAnalyzer
from models.finding import PathEvent, RawFinding
from context.compilation_database import CompilationDatabase
from models.report import AnalyzerFailure

# Clang Static Analyzer checker -> CWE
_CWE_MAP = {
    "core.NullDereference": "CWE-476",
    "core.DivideZero": "CWE-369",
    "core.UndefinedBinaryOperatorResult": "CWE-457",
    "core.uninitialized.Assign": "CWE-457",
    "core.uninitialized.Branch": "CWE-457",
    "core.uninitialized.UndefReturn": "CWE-457",
    "core.StackAddressEscape": "CWE-562",
    "unix.Malloc": "CWE-401",
    "unix.MallocSizeof": "CWE-131",
    "unix.MismatchedDeallocators": "CWE-762",
    "cplusplus.NewDelete": "CWE-401",
    "cplusplus.NewDeleteLeaks": "CWE-401",
    "cplusplus.DoubleFree": "CWE-415",
    "alpha.security.ArrayBound": "CWE-125",
    "alpha.security.ArrayBoundV2": "CWE-125",
    "alpha.security.ReturnPtrRange": "CWE-125",
    "security.insecureAPI.strcpy": "CWE-120",
    "security.insecureAPI.gets": "CWE-120",
    "security.insecureAPI.sprintf": "CWE-120",
    "alpha.core.CastSize": "CWE-704",
    "alpha.cplusplus.DeleteWithNonVirtualDtor": "CWE-1079",
}

_ERROR_CATEGORIES = {"Logic error", "Memory Error", "Memory error", "Unix API"}

_DEFAULT_SKIP_DIRS = {"build", "dist", "third_party", ".git", "CMakeFiles"}
_CPP_EXTS = {".cpp", ".cc", ".cxx"}
_C_EXTS = {".c"}


class ClangStaticAnalyzer(BaseAnalyzer):
    """
    Wrapper around Clang Static Analyzer (clang --analyze).

    Two execution modes:
    - With compile_commands.json: replay original compile flags per translation unit.
    - Without compile_commands.json: recursively analyze files with fallback defaults.
    """

    def __init__(
        self,
        clang_path: str = "clang",
        extra_args: List[str] = None,
        file_extensions: List[str] = None,
        skip_dirs: List[str] = None,
        checkers: List[str] = None,
        show_failures: bool = False,
    ):
        self.clang_path = clang_path
        self.extra_args = extra_args or []
        self.file_extensions = set(file_extensions) if file_extensions else (_CPP_EXTS | _C_EXTS)
        self.skip_dirs = set(skip_dirs) if skip_dirs else _DEFAULT_SKIP_DIRS
        self.checkers = checkers or []
        self.show_failures = show_failures
        self.last_failures: List[AnalyzerFailure] = []

    @staticmethod
    def _has_macro_define(args: List[str], macro_name: str) -> bool:
        prefix = f"-D{macro_name}"
        alt_prefix = f"/D{macro_name}"
        return any(
            arg == prefix
            or arg.startswith(prefix + "=")
            or arg == alt_prefix
            or arg.startswith(alt_prefix + "=")
            for arg in args
        )

    def _build_compat_args(self, is_clang_cl: bool, compile_args: List[str]) -> List[str]:
        # Keep analyzer invocation as close as possible to compile_commands.
        # Injecting __STDC__ for clang-cl can change UCRT non-ANSI name exposure
        # (e.g. timeb/_timeb), which causes false compile errors during analysis.
        return []

    def _execute(self, src_dir: str, compile_commands: str = "") -> str:
        self.last_failures = []
        with tempfile.TemporaryDirectory(prefix="csa_out_") as out_dir:
            if compile_commands and os.path.isfile(compile_commands):
                plist_paths = self._analyze_with_compile_commands(compile_commands, out_dir, src_dir)
            else:
                plist_paths = self._analyze_directory(src_dir, out_dir)

            diagnostics = []
            for plist_path in plist_paths:
                diagnostics.extend(self._load_plist(plist_path))

        return json.dumps(diagnostics, ensure_ascii=False)

    def _parse(self, output: str, src_dir: str) -> List[RawFinding]:
        try:
            diagnostics = json.loads(output)
        except (json.JSONDecodeError, ValueError):
            return []

        findings = []
        for diag in diagnostics:
            check_name = diag.get("check_name", "")
            description = diag.get("description", "")
            category = diag.get("category", "")
            file_path = diag.get("file_path", "")
            line = diag.get("line", 0)
            col = diag.get("col", 0)

            if not file_path or not check_name:
                continue
            # Only filter by checker name when an explicit checker allowlist is provided.
            # Sentinel "__ALL__" means broad enablement without post-parse filtering.
            if self.checkers and "__ALL__" not in self.checkers and check_name not in self.checkers:
                continue

            severity = "error" if category in _ERROR_CATEGORIES else "warning"

            findings.append(
                RawFinding(
                    tool="clang-sa",
                    file_path=file_path,
                    line=line,
                    column=col,
                    severity=severity,
                    defect_id=check_name,
                    message=description,
                    cwe=_CWE_MAP.get(check_name),
                    path_events=[
                        PathEvent(
                            file_path=event.get("file_path", ""),
                            line=event.get("line", 0),
                            column=event.get("col", 0),
                            message=event.get("message", ""),
                            event_kind=event.get("kind", ""),
                            details=event.get("details", {}),
                        )
                        for event in diag.get("path_events", [])
                    ],
                )
            )

        return findings

    def _analyze_with_compile_commands(
        self, compile_commands: str, out_dir: str, src_dir: str = ""
    ) -> List[str]:
        with open(compile_commands, "r", encoding="utf-8") as f:
            entries = json.load(f)
        compilation_db = CompilationDatabase(compile_commands)

        is_clang_cl = os.path.basename(self.clang_path).lower().startswith("clang-cl")
        analyzer_output_args = (
            ["-Xclang", "-analyzer-output", "-Xclang", "plist-multi-file"]
            if is_clang_cl
            else ["-Xanalyzer", "-analyzer-output=plist-multi-file"]
        )
        msvc_include_args = self._get_msvc_include_args() if is_clang_cl else []
        checker_args = self._build_checker_args(is_clang_cl)
        src_dir_norm = os.path.normcase(os.path.realpath(src_dir)) if src_dir else ""

        plist_paths: List[str] = []
        failed: List[AnalyzerFailure] = []
        for i, entry in enumerate(entries):
            work_dir = entry.get("directory", os.path.dirname(compile_commands))
            file_path = entry.get("file", "")
            if file_path and not os.path.isabs(file_path):
                file_path = os.path.realpath(os.path.join(work_dir, file_path))
            ext = os.path.splitext(file_path)[1].lower()
            if ext not in self.file_extensions:
                continue
            if src_dir_norm:
                try:
                    inside_src = os.path.commonpath(
                        [os.path.normcase(os.path.realpath(file_path)), src_dir_norm]
                    ) == src_dir_norm
                except ValueError:
                    inside_src = False
                if not inside_src:
                    continue

            compile_args = compilation_db.args_for(file_path)
            compat_args = self._build_compat_args(is_clang_cl, compile_args)
            out_file = os.path.join(out_dir, f"diag_{i}.plist")

            cmd = (
                [self.clang_path, "--analyze"]
                + analyzer_output_args
                + checker_args
                + ["-o", out_file]
                + msvc_include_args
                + compat_args
                + compile_args
                + self.extra_args
                + [file_path]
            )
            result = subprocess.run(cmd, capture_output=True, text=False, cwd=work_dir)
            if os.path.isfile(out_file):
                plist_paths.append(out_file)
            elif result.returncode != 0:
                stderr_text = self._decode_output(result.stderr)
                failed.append(
                    self._build_failure(
                        analyzer_name="ClangStaticAnalyzer",
                        file_path=file_path,
                        stderr=stderr_text,
                        return_code=result.returncode,
                    )
                )

        if failed:
            self.last_failures.extend(failed)
            if self.show_failures:
                print(f"      [警告] 以下文件分析失败（共 {len(failed)} 个）：")
                for failure in failed:
                    print(
                        f"        - {os.path.basename(failure.file_path)} "
                        f"[{failure.error_category}]: {failure.error_summary}"
                    )

        return plist_paths

    def _analyze_directory(self, src_dir: str, out_dir: str) -> List[str]:
        plist_paths: List[str] = []
        idx = 0
        for root, dirs, files in os.walk(src_dir):
            dirs[:] = [d for d in dirs if d not in self.skip_dirs]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in self.file_extensions:
                    continue

                file_path = os.path.join(root, fname)
                out_file = os.path.join(out_dir, f"diag_{idx}.plist")
                idx += 1

                lang_args = ["-std=c++17"] if ext in _CPP_EXTS else ["-std=c11"]
                checker_args = self._build_checker_args(is_clang_cl=False)
                cmd = (
                    [self.clang_path, "--analyze", "-Xanalyzer", "-analyzer-output=plist-multi-file"]
                    + checker_args
                    + ["-o", out_file]
                    + lang_args
                    + self.extra_args
                    + [file_path]
                )
                result = subprocess.run(cmd, capture_output=True, text=False)
                if os.path.isfile(out_file):
                    plist_paths.append(out_file)
                elif result.returncode != 0:
                    stderr_text = self._decode_output(result.stderr)
                    failure = self._build_failure(
                        analyzer_name="ClangStaticAnalyzer",
                        file_path=file_path,
                        stderr=stderr_text,
                        return_code=result.returncode,
                    )
                    self.last_failures.append(failure)
                    if self.show_failures:
                        print(
                            f"      [警告] {os.path.basename(file_path)} "
                            f"[{failure.error_category}]: {failure.error_summary}"
                        )

        return plist_paths

    def _build_checker_args(self, is_clang_cl: bool) -> List[str]:
        """Build checker flags passed to clang static analyzer."""
        if not self.checkers:
            return []

        # Special sentinel to enable a broad checker set, including alpha.
        if len(self.checkers) == 1 and self.checkers[0] == "__ALL__":
            checker_expr = "core,cplusplus,deadcode,nullability,optin,security,unix,valist,alpha"
        else:
            checker_expr = ",".join(self.checkers)

        opt = f"-analyzer-checker={checker_expr}"
        return ["-Xclang", opt] if is_clang_cl else ["-Xanalyzer", opt]

    @staticmethod
    def _extract_include_trace(lines: List[str]) -> List[str]:
        prefix = "In file included from "
        trace = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(prefix):
                trace.append(stripped[len(prefix):])
        return trace

    @staticmethod
    def _extract_primary_error(lines: List[str]) -> str:
        for line in lines:
            stripped = line.strip()
            if " fatal error: " in stripped or " error: " in stripped:
                return stripped
        return lines[-1].strip() if lines else "unknown error"

    @classmethod
    def _classify_failure(cls, primary_error: str, stderr: str) -> str:
        lower = primary_error.lower()
        stderr_lower = stderr.lower()
        if "file not found" in lower:
            return "missing-header"
        if "implicit instantiation of undefined template" in lower:
            return "missing-include-or-incomplete-type"
        if "use of undeclared identifier" in lower:
            return "undeclared-identifier"
        if any(token in lower for token in ("expected ')'", "expected ';'", "redefinition of")):
            return "macro-or-syntax-compatibility"
        if "no matching function" in lower or "candidate function" in stderr_lower:
            return "type-or-overload-mismatch"
        return "compiler-error"

    @classmethod
    def _build_failure(
        cls,
        analyzer_name: str,
        file_path: str,
        stderr: Optional[str],
        return_code: Optional[int],
    ) -> AnalyzerFailure:
        stderr_text = stderr or ""
        lines = [line for line in stderr_text.splitlines() if line.strip()]
        include_trace = cls._extract_include_trace(lines)
        primary_error = cls._extract_primary_error(lines)
        return AnalyzerFailure(
            analyzer=analyzer_name,
            file_path=file_path,
            error_category=cls._classify_failure(primary_error, stderr_text),
            error_summary=primary_error,
            stderr_excerpt="\n".join(lines[:20]),
            include_trace=include_trace,
            return_code=return_code,
        )

    @staticmethod
    def _decode_output(payload: Optional[bytes]) -> str:
        if not payload:
            return ""
        for enc in ("utf-8", "gbk"):
            try:
                return payload.decode(enc)
            except UnicodeDecodeError:
                continue
        return payload.decode("utf-8", errors="replace")

    @staticmethod
    def _get_msvc_include_args() -> List[str]:
        if winreg is None:
            return []
        include_dirs = []

        for vs_root in [
            r"C:\Program Files\Microsoft Visual Studio",
            r"C:\Program Files (x86)\Microsoft Visual Studio",
        ]:
            if not os.path.isdir(vs_root):
                continue
            for year in sorted(os.listdir(vs_root), reverse=True):
                for edition in ("Community", "Professional", "Enterprise", "BuildTools"):
                    ver_file = os.path.join(
                        vs_root,
                        year,
                        edition,
                        "VC",
                        "Auxiliary",
                        "Build",
                        "Microsoft.VCToolsVersion.default.txt",
                    )
                    if os.path.isfile(ver_file):
                        with open(ver_file) as f:
                            vc_ver = f.read().strip()
                        msvc_inc = os.path.join(
                            vs_root,
                            year,
                            edition,
                            "VC",
                            "Tools",
                            "MSVC",
                            vc_ver,
                            "include",
                        )
                        if os.path.isdir(msvc_inc):
                            include_dirs.append(msvc_inc)
                        break
                if include_dirs:
                    break
            if include_dirs:
                break

        try:
            sdk_key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows Kits\Installed Roots",
                access=winreg.KEY_READ | winreg.KEY_WOW64_32KEY,
            )
            sdk_root, _ = winreg.QueryValueEx(sdk_key, "KitsRoot10")
            winreg.CloseKey(sdk_key)
            sdk_inc = os.path.join(sdk_root, "Include")
            if os.path.isdir(sdk_inc):
                versions = sorted(os.listdir(sdk_inc), reverse=True)
                for ver in versions:
                    for sub in ("ucrt", "shared", "um", "winrt"):
                        d = os.path.join(sdk_inc, ver, sub)
                        if os.path.isdir(d):
                            include_dirs.append(d)
                    if versions:
                        break
        except OSError:
            pass

        return [f"/imsvc{d}" for d in include_dirs]

    @staticmethod
    def _extract_compile_args(entry: dict, file_path: str) -> List[str]:
        arguments = entry.get("arguments", [])
        if arguments:
            raw_args = arguments[1:]
        else:
            command = entry.get("command", "")
            raw_args = (
                [a.replace('\\"', '"') for a in shlex.split(command, posix=False)][1:]
                if command
                else []
            )

        filtered = []
        skip_next = False
        for arg in raw_args:
            if skip_next:
                skip_next = False
                continue

            # stop before linker args; analyzer compile phase should not include them
            if arg == "--" or arg.lower() == "/link":
                break

            if arg in ("-o", "-MF", "-MT", "-MQ"):
                skip_next = True
                continue
            if arg in ("-c", "/c") or arg.startswith("/Fo") or arg.startswith("/Fd"):
                continue
            if arg == file_path:
                continue

            filtered.append(arg)

        return filtered

    @staticmethod
    def _load_plist(plist_path: str) -> List[dict]:
        try:
            with open(plist_path, "rb") as f:
                data = plistlib.load(f)
        except Exception:
            return []

        files = data.get("files", [])
        result = []
        for diag in data.get("diagnostics", []):
            loc = diag.get("location", {})
            file_idx = loc.get("file", 0)
            file_path = files[file_idx] if file_idx < len(files) else ""
            path_events = []
            for event in diag.get("path", []):
                event_loc = event.get("location", {})
                event_file_idx = event_loc.get("file", file_idx)
                event_file = files[event_file_idx] if event_file_idx < len(files) else file_path
                path_events.append(
                    {
                        "file_path": event_file,
                        "line": event_loc.get("line", 0),
                        "col": event_loc.get("col", 0),
                        "message": event.get("extended_message") or event.get("message", ""),
                        "kind": event.get("kind", ""),
                        "details": event,
                    }
                )
            result.append(
                {
                    "check_name": diag.get("check_name", ""),
                    "description": diag.get("description", ""),
                    "category": diag.get("category", ""),
                    "file_path": file_path,
                    "line": loc.get("line", 0),
                    "col": loc.get("col", 0),
                    "path_events": path_events,
                }
            )
        return result

