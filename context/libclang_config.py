"""Configure the libclang dynamic library once for all AST services."""

import os

import clang.cindex as cindex

_configured = False


def _bundled_libclang_path() -> str:
    package_dir = os.path.dirname(cindex.__file__)
    names = ("libclang.dll", "libclang.so", "libclang.dylib")
    candidates = [
        os.path.join(package_dir, "native", name) for name in names
    ] + [
        os.path.join(package_dir, name) for name in names
    ]
    return next((path for path in candidates if os.path.isfile(path)), "")


def configure_libclang(libclang_path: str = ""):
    """Configure an explicit or Python-package-bundled libclang library."""
    global _configured
    if _configured:
        return

    cindex.Config.set_compatibility_check(False)
    selected = libclang_path if libclang_path and os.path.isfile(libclang_path) else ""
    selected = selected or _bundled_libclang_path()
    if selected:
        cindex.Config.set_library_file(selected)
    _configured = True
