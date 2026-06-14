import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class VerdictResult:
    """Agent 从 LLM 输出中解析出的最终裁决"""
    verdict: str                          # TRUE_POSITIVE | FALSE_POSITIVE | UNCERTAIN
    confidence: float
    reasoning: List[str] = field(default_factory=list)
    fixed_code: str = ""
    fix_explanation: str = ""
    parse_error: Optional[str] = None    # 若解析失败，记录原因


def parse_verdict(text: str) -> VerdictResult:
    """
    从 LLM 的最终输出文本中解析裁决结果。
    期望格式：
        VERDICT: TRUE_POSITIVE | FALSE_POSITIVE | UNCERTAIN
        CONFIDENCE: 0.0-1.0
        REASONING:
        - 推理步骤1
        - 推理步骤2
        FIX:
        <修复代码>
        FIX_EXPLANATION:
        <修复说明>
    """
    verdict = "UNCERTAIN"
    confidence = 0.5
    reasoning = []
    fixed_code = ""
    fix_explanation = ""

    # 提取 VERDICT
    m = re.search(r"VERDICT:\s*(TRUE_POSITIVE|FALSE_POSITIVE|UNCERTAIN)", text)
    if m:
        verdict = m.group(1)
    else:
        return VerdictResult(
            verdict="UNCERTAIN",
            confidence=0.3,
            parse_error="未找到 VERDICT 字段",
        )

    # 提取 CONFIDENCE
    m = re.search(r"CONFIDENCE:\s*([0-9.]+)", text)
    if m:
        try:
            confidence = float(m.group(1))
            confidence = max(0.0, min(1.0, confidence))
        except ValueError:
            pass

    # 提取 REASONING 块
    m = re.search(r"REASONING:\s*(.*?)(?=\nFIX:|\nFIX_EXPLANATION:|$)", text, re.DOTALL)
    if m:
        block = m.group(1).strip()
        reasoning = [line.lstrip("- ").strip() for line in block.splitlines() if line.strip()]

    # 提取 FIX（代码块）
    m = re.search(r"FIX:\s*(.*?)(?=\nFIX_EXPLANATION:|$)", text, re.DOTALL)
    if m:
        raw = m.group(1).strip()
        # 去除 markdown 代码围栏
        raw = re.sub(r"^```\w*\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw)
        fixed_code = raw.strip()

    # 提取 FIX_EXPLANATION
    m = re.search(r"FIX_EXPLANATION:\s*(.*?)$", text, re.DOTALL)
    if m:
        fix_explanation = m.group(1).strip()

    return VerdictResult(
        verdict=verdict,
        confidence=confidence,
        reasoning=reasoning,
        fixed_code=fixed_code,
        fix_explanation=fix_explanation,
    )


def parse_verdict_payload(payload: Dict) -> VerdictResult:
    """Validate a structured verdict submitted through a tool call."""
    verdict = str(payload.get("verdict", "UNCERTAIN"))
    if verdict not in {"TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN"}:
        verdict = "UNCERTAIN"
    try:
        confidence = max(0.0, min(1.0, float(payload.get("confidence", 0.3))))
    except (TypeError, ValueError):
        confidence = 0.3
    reasoning = payload.get("reasoning", [])
    if not isinstance(reasoning, list):
        reasoning = [str(reasoning)]
    return VerdictResult(
        verdict=verdict,
        confidence=confidence,
        reasoning=[str(item) for item in reasoning if str(item).strip()],
        fixed_code=str(payload.get("fixed_code", "") or ""),
        fix_explanation=str(payload.get("fix_explanation", "") or ""),
    )
