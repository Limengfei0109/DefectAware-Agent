"""Code-context services with lazy imports to avoid libclang side effects."""

__all__ = [
    "FunctionExtractor",
    "CallGraphBuilder",
    "DataFlowTracer",
    "ContextBuilder",
    "CrossFileSearcher",
    "CompilationDatabase",
]


def __getattr__(name):
    if name == "CompilationDatabase":
        from .compilation_database import CompilationDatabase
        return CompilationDatabase
    if name == "FunctionExtractor":
        from .function_extractor import FunctionExtractor
        return FunctionExtractor
    if name == "CallGraphBuilder":
        from .call_graph import CallGraphBuilder
        return CallGraphBuilder
    if name == "DataFlowTracer":
        from .data_flow import DataFlowTracer
        return DataFlowTracer
    if name == "ContextBuilder":
        from .context_builder import ContextBuilder
        return ContextBuilder
    if name == "CrossFileSearcher":
        from .cross_file_search import CrossFileSearcher
        return CrossFileSearcher
    raise AttributeError(name)
