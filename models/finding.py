from dataclasses import dataclass, field
from typing import Optional, List, Dict


@dataclass
class PathEvent:
    """One event from a static analyzer's diagnostic path."""

    file_path: str = ""
    line: int = 0
    column: int = 0
    message: str = ""
    event_kind: str = ""
    details: Dict = field(default_factory=dict)


@dataclass
class RawFinding:
    """静态分析工具输出的原始 Finding（已标准化）"""
    tool: str                          # "clang-sa"
    file_path: str
    line: int
    column: int
    severity: str                      # "error" | "warning" | "style" | "performance"
    defect_id: str                     # 工具内部规则 ID，如 "nullPointer"
    message: str
    cwe: Optional[str] = None          # CWE 编号（如工具提供）
    path_events: List[PathEvent] = field(default_factory=list)
    extra: Dict = field(default_factory=dict)  # 工具特有的额外字段


@dataclass
class EnrichedFinding:
    """经过上下文提取后的 Finding，传入 Agent 进行分析"""
    # 原始 Finding 信息
    raw: RawFinding

    # 代码上下文
    function_name: str = ""
    function_source: str = ""          # 完整函数体
    surrounding_context: str = ""      # 缺陷行前后各 N 行

    # 调用图信息
    callers: List[str] = field(default_factory=list)    # 调用此函数的函数列表
    callees: List[str] = field(default_factory=list)    # 此函数调用的函数列表

    # 变量信息
    variable_definitions: Dict = field(default_factory=dict)  # 变量名 -> 定义代码

    # 多工具合并信息
    corroborating_tools: List[str] = field(default_factory=list)  # 同时报告此问题的其他工具
    similar_findings: List = field(default_factory=list)           # 同文件同类型的其他 finding

