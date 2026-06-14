import csv
import html
import json
import os
from datetime import datetime
from typing import List

from models.report import DefectReport, FinalReport


class ReportGenerator:
    """Generate safe, machine-readable and human-readable reports."""

    def __init__(self, output_dir: str = "data/reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate(self, report: FinalReport, formats: List[str] = None) -> List[str]:
        formats = formats or ["json", "html"]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        writers = {
            "json": self._write_json,
            "csv": self._write_csv,
            "html": self._write_html,
        }
        return [writers[fmt](report, timestamp) for fmt in formats if fmt in writers]

    def _write_json(self, report: FinalReport, ts: str) -> str:
        path = os.path.join(self.output_dir, f"report_{ts}.json")
        data = {
            "run_id": report.run_id,
            "project_path": report.project_path,
            "generated_at": report.generated_at,
            "summary": {
                "total_raw_findings": report.total_raw_findings,
                "total_analyzed": report.total_analyzed,
                "analyzer_failure_count": len(report.analyzer_failures),
                "true_positives": report.true_positives,
                "false_positives": report.false_positives,
                "uncertain": report.uncertain,
                "false_positive_rate": round(report.false_positive_rate, 4),
                "tool_stats": report.tool_stats,
                "analyzer_failure_stats": report.analyzer_failure_stats,
            },
            "findings": [self._report_to_dict(item) for item in report.reports],
            "analysis_failures": [
                self._failure_to_dict(item) for item in report.analyzer_failures
            ],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return path

    def _write_csv(self, report: FinalReport, ts: str) -> str:
        path = os.path.join(self.output_dir, f"report_{ts}.csv")
        fieldnames = [
            "verdict", "confidence", "tool", "file_path", "line", "defect_id",
            "cwe", "message", "function_name", "fixed_code", "fix_explanation",
            "reasoning", "path_events",
        ]
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
            writer.writeheader()
            for item in report.reports:
                raw = item.finding.raw
                writer.writerow(
                    {
                        "verdict": item.verdict,
                        "confidence": item.confidence,
                        "tool": raw.tool,
                        "file_path": raw.file_path,
                        "line": raw.line,
                        "defect_id": raw.defect_id,
                        "cwe": raw.cwe or "",
                        "message": raw.message,
                        "function_name": item.finding.function_name,
                        "fixed_code": item.fixed_code,
                        "fix_explanation": item.fix_explanation,
                        "reasoning": " | ".join(item.reasoning_chain),
                        "path_events": " | ".join(
                            f"{e.file_path}:{e.line}:{e.column} {e.message}"
                            for e in raw.path_events
                        ),
                    }
                )
        return path

    def _write_html(self, report: FinalReport, ts: str) -> str:
        path = os.path.join(self.output_dir, f"report_{ts}.html")
        finding_rows = "\n".join(self._finding_html(item) for item in report.reports)
        failure_rows = "\n".join(
            self._failure_html(item) for item in report.analyzer_failures
        )
        project = html.escape(report.project_path)
        generated_at = html.escape(report.generated_at)
        document = f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DefectAware 缺陷分析报告 - {ts}</title>
<style>
body{{font-family:Arial,"Microsoft YaHei",sans-serif;margin:0;background:#f5f6f8;color:#20242b}}
header,main{{max-width:1200px;margin:auto;padding:20px}}
header{{background:#20242b;color:white;max-width:none}}
h1,h2{{margin:0 0 12px}} .muted{{color:#697386}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:18px 0}}
.stat,.finding,.failure{{background:white;border:1px solid #dfe3e8;border-radius:6px;padding:14px}}
.finding,.failure{{margin:10px 0}} .finding{{border-left:5px solid #8a94a6}}
.TRUE_POSITIVE{{border-left-color:#c0392b}} .FALSE_POSITIVE{{border-left-color:#218c5b}}
.UNCERTAIN{{border-left-color:#c88400}} .badge{{font-weight:bold}} pre{{overflow:auto;background:#171a21;color:#e6edf3;padding:12px;border-radius:4px;white-space:pre-wrap}}
details summary{{cursor:pointer}} .toolbar{{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0}}
button{{padding:7px 11px;border:1px solid #c8ced8;background:white;border-radius:4px;cursor:pointer}}
.path-event{{padding:6px 0;border-bottom:1px solid #edf0f3}} code{{font-family:Consolas,monospace}}
</style>
</head>
<body>
<header><h1>DefectAware 缺陷分析报告</h1><div>{project}</div><div>{generated_at}</div></header>
<main>
<section class="stats">
<div class="stat"><strong>{report.total_raw_findings}</strong><div class="muted">原始问题</div></div>
<div class="stat"><strong>{report.total_analyzed}</strong><div class="muted">已复核</div></div>
<div class="stat"><strong>{report.true_positives}</strong><div class="muted">真阳性</div></div>
<div class="stat"><strong>{report.false_positives}</strong><div class="muted">假阳性</div></div>
<div class="stat"><strong>{report.uncertain}</strong><div class="muted">不确定</div></div>
<div class="stat"><strong>{len(report.analyzer_failures)}</strong><div class="muted">分析失败</div></div>
</section>
<section><h2>分析失败</h2>{failure_rows or '<div class="muted">无分析失败。</div>'}</section>
<section>
<h2>缺陷复核结果</h2>
<div class="toolbar">
<button onclick="filterFindings('ALL')">全部</button>
<button onclick="filterFindings('TRUE_POSITIVE')">真阳性</button>
<button onclick="filterFindings('FALSE_POSITIVE')">假阳性</button>
<button onclick="filterFindings('UNCERTAIN')">不确定</button>
<button onclick="exportAnnotations()">导出人工标注 JSON</button>
</div>
{finding_rows or '<div class="muted">没有发现可复核的问题。</div>'}
</section>
</main>
<script>
function filterFindings(value){{
 document.querySelectorAll('.finding').forEach(function(node){{
  node.style.display=(value==='ALL'||node.dataset.verdict===value)?'block':'none';
 }});
}}
function annotate(button,value){{
 const card=button.closest('.finding');
 card.dataset.humanVerdict=value;
 card.querySelectorAll('.annotation').forEach(function(item){{item.disabled=false;}});
 localStorage.setItem('csaagent-annotation-'+card.dataset.key,value);
}}
function saveNote(area){{
 const card=area.closest('.finding');
 localStorage.setItem('csaagent-note-'+card.dataset.key,area.value);
}}
function exportAnnotations(){{
 const data=Array.from(document.querySelectorAll('.finding')).map(function(card){{
  return {{key:card.dataset.key,ai_verdict:card.dataset.verdict,
   human_verdict:card.dataset.humanVerdict||null,
   note:card.querySelector('textarea').value}};
 }});
 const blob=new Blob([JSON.stringify(data,null,2)],{{type:'application/json'}});
 const link=document.createElement('a'); link.href=URL.createObjectURL(blob);
 link.download='annotations-{ts}.json'; link.click(); URL.revokeObjectURL(link.href);
}}
document.querySelectorAll('.finding').forEach(function(card){{
 const verdict=localStorage.getItem('csaagent-annotation-'+card.dataset.key);
 const note=localStorage.getItem('csaagent-note-'+card.dataset.key);
 if(verdict) card.dataset.humanVerdict=verdict;
 if(note) card.querySelector('textarea').value=note;
}});
</script>
</body></html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(document)
        return path

    def _finding_html(self, item: DefectReport) -> str:
        raw = item.finding.raw
        reasoning = "".join(f"<li>{html.escape(step)}</li>" for step in item.reasoning_chain)
        path_events = "".join(
            "<div class='path-event'><code>"
            + html.escape(f"{event.file_path}:{event.line}:{event.column}")
            + "</code> "
            + html.escape(event.message)
            + "</div>"
            for event in raw.path_events
        )
        fix = (
            f"<pre>{html.escape(item.fixed_code)}</pre>"
            if item.fixed_code
            else "<div class='muted'>无修复代码。</div>"
        )
        key = html.escape(f"{raw.file_path}:{raw.line}:{raw.defect_id}", quote=True)
        return f"""<article class="finding {html.escape(item.verdict)}" data-verdict="{html.escape(item.verdict)}" data-key="{key}">
<div><span class="badge">{html.escape(item.verdict)}</span> · 置信度 {item.confidence:.0%}</div>
<h3>{html.escape(raw.defect_id)} · {html.escape(os.path.basename(raw.file_path))}:{raw.line}</h3>
<p>{html.escape(raw.message)}</p>
<details><summary>推理与修复</summary><ol>{reasoning or '<li>-</li>'}</ol>{fix}
<p>{html.escape(item.fix_explanation)}</p></details>
<details><summary>静态分析路径事件 ({len(raw.path_events)})</summary>{path_events or '<div class="muted">无路径事件。</div>'}</details>
<div class="toolbar"><strong>人工标注：</strong>
<button class="annotation" onclick="annotate(this,'TRUE_POSITIVE')">真阳性</button>
<button class="annotation" onclick="annotate(this,'FALSE_POSITIVE')">假阳性</button>
<button class="annotation" onclick="annotate(this,'UNCERTAIN')">不确定</button></div>
<textarea oninput="saveNote(this)" rows="3" style="width:100%" placeholder="人工复核备注"></textarea>
</article>"""

    def _failure_html(self, failure) -> str:
        trace = "".join(f"<li>{html.escape(item)}</li>" for item in failure.include_trace)
        return f"""<details class="failure"><summary><strong>{html.escape(os.path.basename(failure.file_path) or failure.file_path)}</strong> · {html.escape(failure.error_category)}</summary>
<p>{html.escape(failure.error_summary)}</p><ul>{trace}</ul>
<pre>{html.escape(failure.stderr_excerpt)}</pre></details>"""

    def _report_to_dict(self, item: DefectReport) -> dict:
        raw = item.finding.raw
        return {
            "verdict": item.verdict,
            "confidence": item.confidence,
            "tool": raw.tool,
            "file_path": raw.file_path,
            "line": raw.line,
            "column": raw.column,
            "severity": raw.severity,
            "defect_id": raw.defect_id,
            "cwe": raw.cwe,
            "message": raw.message,
            "path_events": [
                {
                    "file_path": event.file_path,
                    "line": event.line,
                    "column": event.column,
                    "message": event.message,
                    "event_kind": event.event_kind,
                    "details": event.details,
                }
                for event in raw.path_events
            ],
            "function_name": item.finding.function_name,
            "reasoning_chain": item.reasoning_chain,
            "tool_calls_count": len(item.tool_calls_log),
            "tool_calls_log": item.tool_calls_log,
            "fixed_code": item.fixed_code,
            "fix_explanation": item.fix_explanation,
            "processing_time": round(item.processing_time, 2),
            "llm_tokens_used": item.llm_tokens_used,
            "agent_steps": item.agent_steps,
            "structured_output_success": item.structured_output_success,
            "workflow_mode": item.workflow_mode,
            "workflow_route": item.workflow_route,
            "workflow_trace": item.workflow_trace,
            "budget_exhausted": item.budget_exhausted,
            "evidence_verified": item.evidence_verified,
            "fallback_used": item.fallback_used,
            "schema_rejections": item.schema_rejections,
            "resumed_from_checkpoint": item.resumed_from_checkpoint,
            "error": item.error,
        }

    @staticmethod
    def _failure_to_dict(failure) -> dict:
        return {
            "analyzer": failure.analyzer,
            "file_path": failure.file_path,
            "error_category": failure.error_category,
            "error_summary": failure.error_summary,
            "stderr_excerpt": failure.stderr_excerpt,
            "include_trace": failure.include_trace,
            "return_code": failure.return_code,
        }
