import os
from typing import Dict, List, Tuple

import yaml

from agent import build_verification_engine
from analyzers import ClangStaticAnalyzer, Deduplicator
from context import ContextBuilder
from models.finding import EnrichedFinding, RawFinding
from models.report import AnalyzerFailure, DefectReport, FinalReport
from observability import record_report_if_enabled
from pipeline.checkpoint import CheckpointStore


class Runner:
    """Main pipeline runner: CSA -> context -> agent verification."""

    def __init__(self, config_path: str = "config.yaml"):
        with open(config_path, "r", encoding="utf-8") as f:
            self.cfg = yaml.safe_load(f)

        tools_cfg = self.cfg.get("tools", {})
        llm_cfg = self.cfg.get("llm", {})
        agent_cfg = self.cfg.get("agent", {})
        analysis_cfg = self.cfg.get("analysis", {})
        report_cfg = self.cfg.get("report", {})

        libclang_path = tools_cfg.get("libclang_path", "")
        compile_args = analysis_cfg.get("compile_args", ["-std=c++17"])
        self.show_analyzer_failures = (
            analysis_cfg.get("show_analyzer_failures", False)
            or report_cfg.get("show_analyzer_failures", False)
        )

        self.analyzers = []
        if tools_cfg.get("clang_sa"):
            skip_dirs = analysis_cfg.get("skip_dirs", [])
            file_exts = analysis_cfg.get("file_extensions", [])
            checkers = tools_cfg.get("clang_sa_checkers", [])
            extra_args = analysis_cfg.get("clang_sa_extra_args", [])
            self.analyzers.append(
                ClangStaticAnalyzer(
                    clang_path=tools_cfg["clang_sa"],
                    extra_args=extra_args,
                    skip_dirs=skip_dirs,
                    file_extensions=file_exts,
                    checkers=checkers,
                    show_failures=self.show_analyzer_failures,
                )
            )

        self.deduplicator = Deduplicator()
        self.context_builder = ContextBuilder(libclang_path, compile_args)
        self.agent = build_verification_engine(llm_cfg, agent_cfg, libclang_path, compile_args)
        reliability = self.cfg.get("reliability", {})
        self.checkpoints = (
            CheckpointStore(
                reliability.get("checkpoint_dir", "data/checkpoints"),
                namespace=CheckpointStore.namespace_for(self.cfg),
            )
            if reliability.get("checkpoint_enabled", True)
            else None
        )

    def run(self, src_dir: str, compile_commands: str = "") -> FinalReport:
        self.context_builder.configure_compile_commands(compile_commands)
        self.agent.configure_environment(src_dir, compile_commands)
        print("[1/4] Running Clang Static Analyzer...")
        raw_findings, analyzer_failures = self._run_analyzers(src_dir, compile_commands)
        print(f"      Raw findings: {len(raw_findings)}")
        if analyzer_failures and self.show_analyzer_failures:
            print(f"      Analyzer failures: {len(analyzer_failures)}")

        print("[2/4] Deduplicating findings...")
        deduplicated = self.deduplicator.deduplicate(raw_findings)
        print(f"      Deduplicated findings: {len(deduplicated)}")

        print("[3/4] Building code context...")
        enriched = self.context_builder.enrich_batch(deduplicated)

        print(f"[4/4] Agent verification ({len(enriched)} findings)...")
        reports = self._run_agent(enriched)

        final = self._build_final_report(src_dir, raw_findings, reports, analyzer_failures)
        run_id = record_report_if_enabled(
            final,
            self.cfg,
            {"compile_commands": os.path.abspath(compile_commands) if compile_commands else ""},
        )
        if run_id:
            print(f"      Trace run_id: {run_id}")
        return final

    def _run_analyzers(
        self, src_dir: str, compile_commands: str
    ) -> Tuple[List[RawFinding], List[AnalyzerFailure]]:
        all_findings: List[RawFinding] = []
        all_failures: List[AnalyzerFailure] = []
        for analyzer in self.analyzers:
            name = type(analyzer).__name__
            print(f"      Running {name}...")
            try:
                findings = analyzer.run(src_dir, compile_commands)
                print(f"      {name}: {len(findings)} findings")
                all_findings.extend(findings)
                all_failures.extend(getattr(analyzer, "last_failures", []))
            except Exception as e:
                print(f"      [Warning] {name} failed: {e}")
                all_failures.append(
                    AnalyzerFailure(
                        analyzer=name,
                        file_path=src_dir,
                        error_category="analyzer-exception",
                        error_summary=str(e),
                        stderr_excerpt=str(e),
                    )
                )
        return all_findings, all_failures

    def _run_agent(self, enriched: List[EnrichedFinding]) -> List[DefectReport]:
        reports = []
        for i, ef in enumerate(enriched, 1):
            print(f"      [{i}/{len(enriched)}] Analyze: {ef.raw.file_path}:{ef.raw.line} ({ef.raw.defect_id})")
            cached = self.checkpoints.load(ef) if self.checkpoints else None
            if cached:
                report = self.checkpoints.restore_report(ef, cached)
                print(f"             -> resumed {report.verdict} from checkpoint")
                reports.append(report)
                continue
            try:
                report = self.agent.verify(ef)
                verdict_label = {
                    "TRUE_POSITIVE": "TRUE_POSITIVE",
                    "FALSE_POSITIVE": "FALSE_POSITIVE",
                    "UNCERTAIN": "UNCERTAIN",
                }.get(report.verdict, report.verdict)
                print(f"             -> {verdict_label} (confidence {report.confidence:.2f})")
                reports.append(report)
                if self.checkpoints:
                    self.checkpoints.save(ef, self.checkpoints.report_payload(report))
            except Exception as e:
                print(f"             -> [Error] {e}")
                reports.append(
                    DefectReport(
                        finding=ef,
                        verdict="UNCERTAIN",
                        confidence=0.0,
                        error=str(e),
                    )
                )
        return reports

    def _build_final_report(
        self,
        src_dir: str,
        raw: List[RawFinding],
        reports: List[DefectReport],
        analyzer_failures: List[AnalyzerFailure],
    ) -> FinalReport:
        from datetime import datetime

        tp = sum(1 for r in reports if r.verdict == "TRUE_POSITIVE")
        fp = sum(1 for r in reports if r.verdict == "FALSE_POSITIVE")
        uc = sum(1 for r in reports if r.verdict == "UNCERTAIN")
        total = len(reports)
        fp_rate = fp / total if total > 0 else 0.0

        tool_stats: Dict[str, int] = {}
        for f in raw:
            tool_stats[f.tool] = tool_stats.get(f.tool, 0) + 1

        analyzer_failure_stats: Dict[str, int] = {}
        for failure in analyzer_failures:
            analyzer_failure_stats[failure.analyzer] = analyzer_failure_stats.get(failure.analyzer, 0) + 1

        return FinalReport(
            project_path=src_dir,
            total_raw_findings=len(raw),
            total_analyzed=total,
            true_positives=tp,
            false_positives=fp,
            uncertain=uc,
            false_positive_rate=fp_rate,
            reports=reports,
            tool_stats=tool_stats,
            analyzer_failures=analyzer_failures,
            analyzer_failure_stats=analyzer_failure_stats,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
