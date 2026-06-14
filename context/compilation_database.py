import json
import os
import shlex
from typing import Dict, List


class CompilationDatabase:
    """Provides sanitized, per-file arguments from compile_commands.json."""

    _PATH_FLAGS = {"-I", "-isystem", "-include", "-imacros", "-iquote", "/I", "/FI"}
    _SKIP_WITH_VALUE = {"-o", "-MF", "-MT", "-MQ"}

    def __init__(self, path: str = "", default_args: List[str] = None):
        self.default_args = list(default_args or ["-std=c++17"])
        self.path = ""
        self._args_by_file: Dict[str, List[str]] = {}
        self._directory_by_file: Dict[str, str] = {}
        if path:
            self.load(path)

    @staticmethod
    def _key(path: str) -> str:
        return os.path.normcase(os.path.realpath(path))

    def load(self, path: str) -> None:
        self.path = ""
        self._args_by_file.clear()
        self._directory_by_file.clear()
        if not path or not os.path.isfile(path):
            return

        with open(path, "r", encoding="utf-8") as f:
            entries = json.load(f)

        for entry in entries:
            directory = os.path.realpath(entry.get("directory") or os.path.dirname(path))
            file_path = entry.get("file", "")
            if not file_path:
                continue
            if not os.path.isabs(file_path):
                file_path = os.path.join(directory, file_path)
            file_path = os.path.realpath(file_path)
            key = self._key(file_path)
            self._args_by_file[key] = self._extract_args(entry, file_path, directory)
            self._directory_by_file[key] = directory

        self.path = os.path.realpath(path)

    def args_for(self, file_path: str) -> List[str]:
        return list(self._args_by_file.get(self._key(file_path), self.default_args))

    def directory_for(self, file_path: str) -> str:
        return self._directory_by_file.get(
            self._key(file_path), os.path.dirname(os.path.realpath(file_path))
        )

    def files(self) -> List[str]:
        return list(self._args_by_file)

    @classmethod
    def _extract_args(cls, entry: dict, file_path: str, directory: str) -> List[str]:
        arguments = entry.get("arguments") or []
        if arguments:
            raw_args = list(arguments[1:])
        else:
            command = entry.get("command", "")
            raw_args = (
                [arg.replace('\\"', '"') for arg in shlex.split(command, posix=False)][1:]
                if command
                else []
            )

        result: List[str] = []
        skip_next = False
        path_value_flag = ""
        source_key = cls._key(file_path)

        for arg in raw_args:
            if skip_next:
                skip_next = False
                continue
            if path_value_flag:
                result.append(cls._absolute_arg_path(arg, directory))
                path_value_flag = ""
                continue
            if arg == "--" or arg.lower() == "/link":
                break
            if arg in cls._SKIP_WITH_VALUE:
                skip_next = True
                continue
            if arg in ("-c", "/c") or arg.startswith("/Fo") or arg.startswith("/Fd"):
                continue
            if cls._key(cls._absolute_arg_path(arg, directory)) == source_key:
                continue
            if arg in cls._PATH_FLAGS:
                result.append(arg)
                path_value_flag = arg
                continue

            converted = cls._convert_joined_path_arg(arg, directory)
            result.append(converted)

        return result

    @staticmethod
    def _absolute_arg_path(value: str, directory: str) -> str:
        value = value.strip('"')
        if not value or value.startswith("-") or (value.startswith("/") and not os.path.exists(value)):
            return value
        return value if os.path.isabs(value) else os.path.realpath(os.path.join(directory, value))

    @classmethod
    def _convert_joined_path_arg(cls, arg: str, directory: str) -> str:
        for prefix in ("-I", "/I", "/FI"):
            if arg.startswith(prefix) and len(arg) > len(prefix):
                value = arg[len(prefix):].strip('"')
                if not os.path.isabs(value):
                    value = os.path.realpath(os.path.join(directory, value))
                return prefix + value
        return arg
