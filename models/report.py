from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .finding import EnrichedFinding


@dataclass
class AnalyzerFailure:
    """Static analyzer failure for a single translation unit or analyzer run."""

    analyzer: str
    file_path: str
    error_category: str
    error_summary: str
    stderr_excerpt: str = ""
    include_trace: List[str] = field(default_factory=list)
    return_code: Optional[int] = None


@dataclass
class DefectReport:
    """Agent verdict and reasoning for a single finding."""

    finding: EnrichedFinding
    verdict: str
    confidence: float
    reasoning_chain: List[str] = field(default_factory=list)
    tool_calls_log: List[Dict] = field(default_factory=list)
    fixed_code: str = ""
    fix_explanation: str = ""
    processing_time: float = 0.0
    llm_tokens_used: int = 0
    agent_steps: int = 0
    structured_output_success: bool = False
    workflow_mode: str = ""
    workflow_route: str = ""
    workflow_trace: List[Dict] = field(default_factory=list)
    budget_exhausted: bool = False
    evidence_verified: bool = False
    fallback_used: bool = False
    schema_rejections: int = 0
    resumed_from_checkpoint: bool = False
    error: Optional[str] = None


@dataclass
class FinalReport:
    """Final project-level analysis summary."""

    project_path: str
    total_raw_findings: int
    total_analyzed: int
    true_positives: int
    false_positives: int
    uncertain: int
    false_positive_rate: float
    reports: List[DefectReport] = field(default_factory=list)
    tool_stats: Dict = field(default_factory=dict)
    analyzer_failures: List[AnalyzerFailure] = field(default_factory=list)
    analyzer_failure_stats: Dict[str, int] = field(default_factory=dict)
    generated_at: str = ""
    run_id: str = ""
