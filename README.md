# DefectAware Agent

DefectAware Agent is a production-oriented multi-agent system for verifying
C/C++ static-analysis findings:

1. Run Clang Static Analyzer.
2. Build code context.
3. Use an LLM agent to classify findings.
4. Generate reports (`json`, `html`, `csv`).

## Controlled Multi-Agent Workflow

Set `agent.mode: controlled_workflow` to use the bounded production workflow:

```text
deterministic CWE router
  -> Investigator (tools only, no verdict)
  -> Verifier (evidence-only verdict, no investigation tools)
  -> Critic (rejects unsupported conclusions)
```

## Observability Dashboard

When `observability.enabled` is true, every completed scan or seed experiment
is persisted to SQLite with a generated `run_id`. Stored data includes finding
verdicts, workflow stages, prompts, tool observations, tokens, latency, budget
status, and failure reasons.

```bash
python run_dashboard.py --db data/observability/traces.db --port 8000
```

Open `http://127.0.0.1:8000` to inspect runs, model comparisons, defect
distributions, tool success, and full per-finding traces.

Attach evaluator metrics to a recorded run to display model quality and
per-defect accuracy:

```bash
python -m observability.import_evaluation \
  --run-id <run-id> \
  --metrics data/evaluations/controlled-workflow.json
```

`run_ablation.py` and `run_seed_ablation.py` attach their generated metrics
automatically when observability is enabled.

## Reliability And Security

The controlled workflow applies production-oriented safety controls:

- Strict schema validation for tool calls and structured Agent outputs
- Automatic structured-output retry, followed by `UNCERTAIN` on repeated failure
- Tool argument validation, project-root path enforcement, and result caching
- Token, tool-call, step, request-timeout, and retry budgets
- Optional model fallback after primary-provider failure
- Prompt-injection boundaries around source code and tool observations
- `EvidenceVerifier` validation of cited source lines before accepting TP/FP
- Per-finding checkpoints for interrupted-run recovery

Definitive verdict reasoning must cite concrete evidence such as
`src/example.cpp:L42`. If the referenced line does not exist or is unrelated
to the claim, the result is downgraded to `UNCERTAIN`.

```yaml
llm:
  provider: claude
  model: primary-model
  timeout: 120
  fallback:
    provider: local
    model: fallback-model
    api_base: http://127.0.0.1:11434/v1
    max_retries: 1

agent:
  safety:
    structured_output_retries: 2
    evidence_verifier_enabled: true
    require_line_citation: true
    tool_cache_enabled: true
    max_argument_length: 4096

reliability:
  checkpoint_enabled: true
  checkpoint_dir: data/checkpoints
```

Checkpoint keys include source content and the relevant model/Agent
configuration, so changed code or experiment settings do not reuse stale
verdicts.

The router limits which tools each defect category may use. The workflow also
enforces tool-call and token budgets, downgrades unsupported or over-budget
results to `UNCERTAIN`, and records a stage-by-stage `workflow_trace` in JSON
reports.

```yaml
agent:
  mode: controlled_workflow
  confidence_threshold: 0.7
  workflow:
    max_investigator_steps: 6
    max_tool_calls: 6
    token_budget: 30000
    critic_enabled: true
```

This repository now supports being used directly as a GitHub Action.

## Run Locally

```bash
python main.py /path/to/src \
  --config config.yaml \
  --compile-commands /path/to/compile_commands.json \
  --output-format json html
```

Useful CI flags:

- `--output-dir data/reports`
- `--summary-json data/reports/csa_summary.json`
- `--fail-on any_issue`
- `--fail-confidence 0.7`

## Use As GitHub Action

In a target repository workflow:

```yaml
name: csaagent-scan

on:
  pull_request:
  push:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build compile_commands.json (example with CMake)
        run: |
          cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

      - name: Run DefectAware Agent
        id: csa
        uses: <your-github-username>/DefectAware-Agent@main
        with:
          src-dir: .
          compile-commands: build/compile_commands.json
          api-key: ${{ secrets.CSA_LLM_API_KEY }}
          output-format: "json html"
          fail-on: "never"
```

## Action Inputs

- `src-dir`: source directory to scan, default `.`
- `config`: config path; empty uses `configs/config.ci.yaml`
- `compile-commands`: optional compile database path
- `output-dir`: report directory, default `data/reports`
- `output-format`: e.g. `json html`
- `fail-on`: `never|true_positive|uncertain|analyzer_failure|true_positive_or_uncertain|any_issue`
- `fail-confidence`: confidence threshold used by fail policy
- `api-key`: API key exposed as `API_KEY` for config

## Action Outputs

- `json-report`: latest JSON report path
- `html-report`: latest HTML report path
- `summary-json`: machine-readable summary path

## Agent Evaluation

The offline evaluator compares a generated JSON report with manually reviewed
ground-truth labels. It measures verdict quality, tool-use quality, evidence
coverage, structured-output reliability, latency, tokens, and estimated cost.

Collect real CSA findings without an API key:

```bash
python make_compile_commands.py evaluation/fixtures/csa_smoke \
  --compiler clang \
  --output data/cache/csa-smoke-compile-commands.json

python collect_findings.py evaluation/fixtures/csa_smoke \
  --config configs/config.ndk.yaml \
  --compile-commands data/cache/csa-smoke-compile-commands.json \
  --output data/reports/csa-smoke-findings.json
```

`configs/config.ndk.yaml` uses local Ollama at `http://127.0.0.1:11434/v1`
with `qwen3:8b`. Change `api_base` and `model` for another compatible
server, or use `config.yaml` with `API_KEY` for the configured hosted provider.

For a reproducible 50-case TP/FP benchmark without access to private source,
generate labels and seed findings from the public NIST Juliet suite:

```bash
python prepare_juliet_benchmark.py evaluation/external/juliet \
  --limit 50 \
  --labels-output evaluation/datasets/juliet_v1_labels.json \
  --report-output evaluation/datasets/juliet_v1_seed_report.json
```

Run the included example:

```bash
python evaluate.py run \
  --labels evaluation/datasets/example_labels.json \
  --report evaluation/examples/example_report.json \
  --name react-tools \
  --price-per-million-tokens 2 \
  --output data/evaluations/react-tools.json
```

Compare models or ablation variants after evaluating each report:

```bash
python evaluate.py compare \
  data/evaluations/direct-llm.json \
  data/evaluations/context-only.json \
  data/evaluations/react-tools.json
```

Create a balanced pending-review candidate set from real reports:

```bash
python evaluate.py prepare data/reports/report_*.json \
  --name gme-v1 \
  --limit 50 \
  --output evaluation/datasets/gme_v1_labels.json
```

Run the Agent ablations (`direct_llm`, `context_only`, `react_tools`,
`react_specialized`, and `controlled_workflow`) against the same source revision:

```bash
python run_ablation.py /path/to/src \
  --config config.yaml \
  --compile-commands /path/to/compile_commands.json \
  --labels evaluation/datasets/gme_v1_labels.json
```

Each label case supports:

- `match`: finding identity (`file_path`, `line`, `defect_id`, optional `cwe`)
- `expected_verdict`: manually reviewed verdict
- `required_tools`: tools the Agent must use to obtain essential evidence
- `optional_tools`: useful but non-essential tools
- `required_evidence`: case-insensitive evidence phrases expected in reasoning or observations

Use the same label dataset for every model and ablation run. Keep the model,
prompt variant, temperature, and price in the run name or experiment metadata
so comparisons remain reproducible.
