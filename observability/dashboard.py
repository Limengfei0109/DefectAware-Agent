import json
import os

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from .trace_store import TraceStore


DB_PATH = os.getenv("DEFECTAWARE_TRACE_DB", "data/observability/traces.db")
store = TraceStore(DB_PATH)
app = FastAPI(title="DefectAware Observability")


def _loads(value, default):
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


@app.get("/api/summary")
def summary():
    runs = store.query(
        """
        SELECT COUNT(*) AS runs, COALESCE(SUM(total_findings), 0) AS findings,
               COALESCE(SUM(total_tokens), 0) AS tokens,
               COALESCE(AVG(total_latency_seconds), 0) AS avg_run_latency,
               COALESCE(SUM(failure_count), 0) AS failures
        FROM runs
        """
    )[0]
    tools = store.query(
        """
        SELECT COUNT(*) AS calls, COALESCE(AVG(success), 0) AS success_rate
        FROM tool_calls
        """
    )[0]
    return {**runs, **tools}


@app.get("/api/runs")
def runs():
    return store.query(
        """
        SELECT r.*,
               json_extract(e.metrics_json, '$.verdict_accuracy') AS verdict_accuracy,
               json_extract(e.metrics_json, '$.tp_f1') AS tp_f1
        FROM runs r
        LEFT JOIN evaluations e ON e.evaluation_id = (
            SELECT MAX(e2.evaluation_id) FROM evaluations e2 WHERE e2.run_id = r.run_id
        )
        ORDER BY r.created_at DESC
        """
    )


@app.get("/api/runs/{run_id}")
def run_detail(run_id: str):
    run = store.query("SELECT * FROM runs WHERE run_id = ?", (run_id,))
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    findings = store.query(
        "SELECT * FROM findings WHERE run_id = ? ORDER BY finding_id", (run_id,)
    )
    for finding in findings:
        finding["reasoning"] = _loads(finding.pop("reasoning_json"), [])
        finding["events"] = store.query(
            "SELECT * FROM events WHERE finding_id = ? ORDER BY sequence",
            (finding["finding_id"],),
        )
        finding["tool_calls"] = store.query(
            "SELECT * FROM tool_calls WHERE finding_id = ? ORDER BY sequence",
            (finding["finding_id"],),
        )
    return {"run": run[0], "findings": findings}


@app.get("/api/analytics")
def analytics():
    evaluation_rows = store.query(
        """
        SELECT r.run_id, r.model, r.agent_mode, e.metrics_json
        FROM evaluations e JOIN runs r ON r.run_id = e.run_id
        ORDER BY e.evaluation_id DESC
        """
    )
    model_quality = []
    defect_accuracy = []
    for row in evaluation_rows:
        metrics = _loads(row.pop("metrics_json"), {})
        model_quality.append(
            {
                **row,
                "verdict_accuracy": metrics.get("verdict_accuracy"),
                "tp_f1": metrics.get("tp_f1"),
                "average_tokens": metrics.get("average_tokens"),
                "average_latency_seconds": metrics.get("average_latency_seconds"),
            }
        )
        for defect_id, values in metrics.get("by_defect", {}).items():
            defect_accuracy.append(
                {
                    **row,
                    "defect_id": defect_id,
                    "cases": values.get("cases", 0),
                    "accuracy": values.get("accuracy", 0),
                }
            )
    return {
        "models": store.query(
            """
            SELECT model, agent_mode, COUNT(*) AS runs,
                   AVG(total_tokens) AS avg_tokens,
                   AVG(total_latency_seconds) AS avg_latency,
                   SUM(true_positives) AS true_positives,
                   SUM(false_positives) AS false_positives,
                   SUM(uncertain) AS uncertain
            FROM runs GROUP BY model, agent_mode ORDER BY runs DESC
            """
        ),
        "defects": store.query(
            """
            SELECT defect_id, COUNT(*) AS findings,
                   AVG(confidence) AS avg_confidence,
                   AVG(tokens) AS avg_tokens,
                   AVG(latency_seconds) AS avg_latency,
                   SUM(verdict = 'TRUE_POSITIVE') AS true_positives,
                   SUM(verdict = 'FALSE_POSITIVE') AS false_positives,
                   SUM(verdict = 'UNCERTAIN') AS uncertain
            FROM findings GROUP BY defect_id ORDER BY findings DESC
            """
        ),
        "failures": store.query(
            """
            SELECT failure_reason, COUNT(*) AS count
            FROM findings WHERE failure_reason != ''
            GROUP BY failure_reason ORDER BY count DESC
            """
        ),
        "model_quality": model_quality,
        "defect_accuracy": defect_accuracy,
    }


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return HTMLResponse(
        """<!doctype html>
<html><head><meta charset="utf-8"><title>DefectAware Observability</title>
<style>
body{font-family:Arial,sans-serif;margin:0;background:#f4f6f8;color:#20242b}
header,main{padding:20px;max-width:1300px;margin:auto}header{max-width:none;background:#20242b;color:white}
.cards,.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.card,section{background:white;border:1px solid #dfe3e8;border-radius:8px;padding:14px;margin:12px 0}
table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid #eee;padding:8px;font-size:13px}
button{cursor:pointer}pre{white-space:pre-wrap;max-height:320px;overflow:auto;background:#171a21;color:#e6edf3;padding:10px}
</style></head>
<body><header><h1>DefectAware Observability</h1></header><main>
<div id="summary" class="cards"></div>
<section><h2>Runs</h2><table><thead><tr><th>Created</th><th>Model</th><th>Mode</th><th>Findings</th><th>Tokens</th><th>Latency</th><th>Accuracy</th><th></th></tr></thead><tbody id="runs"></tbody></table></section>
<section><h2>Model Comparison</h2><div id="models"></div></section>
<section><h2>Evaluated Model Quality</h2><div id="quality"></div></section>
<section><h2>Defect Distribution</h2><div id="defects"></div></section>
<section><h2>Accuracy By Defect</h2><div id="accuracy"></div></section>
<section><h2>Selected Run Trace</h2><div id="trace">Select a run.</div></section>
</main><script>
const esc=(v)=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const table=(rows)=>'<table><thead><tr>'+Object.keys(rows[0]||{}).map(x=>`<th>${esc(x)}</th>`).join('')+'</tr></thead><tbody>'+rows.map(r=>'<tr>'+Object.values(r).map(x=>`<td>${esc(x)}</td>`).join('')+'</tr>').join('')+'</tbody></table>';
async function load(){
 const s=await fetch('/api/summary').then(r=>r.json());
 summary.innerHTML=Object.entries(s).map(([k,v])=>`<div class="card"><b>${esc(v)}</b><div>${esc(k)}</div></div>`).join('');
 const rs=await fetch('/api/runs').then(r=>r.json());
 runs.innerHTML=rs.map(r=>`<tr><td>${esc(r.created_at)}</td><td>${esc(r.model)}</td><td>${esc(r.agent_mode)}</td><td>${esc(r.total_findings)}</td><td>${esc(r.total_tokens)}</td><td>${esc(r.total_latency_seconds.toFixed(2))}s</td><td>${esc(r.verdict_accuracy??'-')}</td><td><button onclick="detail('${r.run_id}')">Trace</button></td></tr>`).join('');
 const a=await fetch('/api/analytics').then(r=>r.json()); models.innerHTML=table(a.models); quality.innerHTML=table(a.model_quality); defects.innerHTML=table(a.defects); accuracy.innerHTML=table(a.defect_accuracy);
}
async function detail(id){const d=await fetch('/api/runs/'+id).then(r=>r.json()); trace.innerHTML=d.findings.map(f=>`<details class="card"><summary>${esc(f.defect_id)} ${esc(f.file_path)}:${esc(f.line)} - ${esc(f.verdict)}</summary><h4>Reasoning</h4><pre>${esc(JSON.stringify(f.reasoning,null,2))}</pre><h4>Events</h4><pre>${esc(JSON.stringify(f.events,null,2))}</pre><h4>Tool Calls</h4><pre>${esc(JSON.stringify(f.tool_calls,null,2))}</pre></details>`).join('');}
load();
</script></body></html>"""
    )
