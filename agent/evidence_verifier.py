import os
import re
from typing import Dict, List, Tuple

from models.finding import EnrichedFinding
from .verdict import VerdictResult


class EvidenceVerifier:
    """Verify that concrete line citations exist in source or collected observations."""

    LINE_PATTERN = re.compile(
        r"(?:(?P<path>[\w./\\-]+\.[ch](?:pp|xx|c|h)?)[:#])?[Ll](?:ine\s*)?(?P<line>\d+)",
        re.IGNORECASE,
    )
    STOP_WORDS = {
        "line", "code", "source", "file", "the", "a", "an", "is", "at", "in",
        "on", "of", "to", "and", "or", "this", "that", "shows", "contains",
    }

    def __init__(self, enabled: bool = True, require_citation: bool = True):
        self.enabled = enabled
        self.require_citation = require_citation
        self.project_root = ""

    def configure_environment(self, project_root: str):
        self.project_root = os.path.realpath(project_root) if project_root else ""

    def verify(
        self,
        finding: EnrichedFinding,
        verdict: VerdictResult,
        evidence: List[Dict],
    ) -> Tuple[bool, List[str]]:
        if not self.enabled or verdict.verdict == "UNCERTAIN":
            return True, []
        reasoning = "\n".join(verdict.reasoning)
        citations = list(self.LINE_PATTERN.finditer(reasoning))
        if not citations and self.require_citation:
            return False, ["Definitive verdict does not cite a concrete code line."]

        evidence_text = "\n".join(str(item.get("observation", "")) for item in evidence)
        issues = []
        for citation in citations:
            line = int(citation.group("line"))
            path = citation.group("path") or finding.raw.file_path
            claim = self._claim_for(reasoning, citation.start(), citation.end())
            source_line = self._line_content(path, line)
            observation = self._observation_context(evidence_text, line)
            if self._related(claim, source_line) or self._related(claim, observation):
                continue
            issues.append(
                f"Cited line {line} does not contain code related to the claimed evidence."
            )
        return not issues, issues

    @staticmethod
    def _claim_for(text: str, start: int, end: int) -> str:
        left = max(text.rfind("\n", 0, start), text.rfind(".", 0, start)) + 1
        right_candidates = [
            value for value in (text.find("\n", end), text.find(".", end)) if value >= 0
        ]
        right = min(right_candidates) if right_candidates else len(text)
        return text[left:right]

    @classmethod
    def _tokens(cls, text: str) -> set:
        return {
            token.lower()
            for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text or "")
            if token.lower() not in cls.STOP_WORDS
            and not re.fullmatch(r"l\d+", token.lower())
        }

    @classmethod
    def _related(cls, claim: str, evidence: str) -> bool:
        return bool(cls._tokens(claim) & cls._tokens(evidence))

    @staticmethod
    def _observation_context(text: str, line: int) -> str:
        return "\n".join(
            item
            for item in text.splitlines()
            if re.search(rf"(?<!\d)[Ll](?:ine\s*)?{line}(?!\d)", item)
            or re.search(rf"^\s*{line}\s*\|", item)
            or re.search(rf":{line}(?::|\b)", item)
        )

    def _line_content(self, path: str, line: int) -> str:
        if not self.project_root or line < 1:
            return ""
        candidate = path if os.path.isabs(path) else os.path.join(self.project_root, path)
        candidate = os.path.realpath(candidate)
        try:
            inside = os.path.normcase(os.path.commonpath([candidate, self.project_root])) == (
                os.path.normcase(self.project_root)
            )
            if not inside:
                return ""
            with open(candidate, "r", encoding="utf-8", errors="replace") as file:
                for current, content in enumerate(file, start=1):
                    if current == line:
                        return content.strip()
        except (OSError, ValueError):
            return ""
        return ""
