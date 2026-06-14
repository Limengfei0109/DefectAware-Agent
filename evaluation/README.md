# DefectAware Agent Evaluation Guide

This directory contains the offline evaluation protocol for Agent experiments.
The same reviewed dataset must be used for every model and ablation run.

## Labeling Workflow

1. Run DefectAware Agent on a fixed source revision and save the JSON report.
2. Review each finding without using the Agent verdict as the ground truth.
3. Confirm the verdict from source code, analyzer path events, build settings,
   and runtime or test evidence when available.
4. Add one case to a labels JSON file.
5. Have a second reviewer check ambiguous cases when possible.
6. Keep unresolved cases as `UNCERTAIN`; do not force a TP or FP label.

Do not change labels after seeing which experiment performs better unless the
original label is demonstrably wrong. Record label changes in version control.

## Case Fields

```json
{
  "id": "null-deref-001",
  "match": {
    "file_path": "src/example.cpp",
    "line": 42,
    "defect_id": "core.NullDereference",
    "cwe": "CWE-476"
  },
  "expected_verdict": "TRUE_POSITIVE",
  "required_tools": ["get_function_context"],
  "optional_tools": ["find_variable_definition", "search_null_checks"],
  "required_evidence": ["pointer can be null", "dereference"],
  "notes": "Why the human reviewer chose this verdict."
}
```

- `required_tools` should contain only tools necessary to resolve this case.
- `optional_tools` contains useful calls that should not count as invalid.
- `required_evidence` uses stable, case-insensitive phrases expected in the
  Agent reasoning or tool observations.
- `notes` should explain the human decision and is not used by the evaluator.

## Recommended Dataset

Start with 50 reviewed cases, then grow to at least 100:

| Category | Target |
| --- | ---: |
| True positives | 40% |
| False positives | 40% |
| Genuinely uncertain | 20% |
| Requires cross-file evidence | at least 25% |
| Each major CWE category | at least 10 cases |

Keep a fixed test set separate from examples used while changing prompts.

## Reproducible Juliet Benchmark

When private production source is unavailable, use the public NIST Juliet
C/C++ test suite. Juliet explicitly marks vulnerable `bad` paths and safe
`good` paths, allowing a balanced reviewed benchmark without inventing labels.

```bash
python prepare_juliet_benchmark.py evaluation/external/juliet \
  --limit 50 \
  --labels-output evaluation/datasets/juliet_v1_labels.json \
  --report-output evaluation/datasets/juliet_v1_seed_report.json
```

Run one Agent configuration against the seed findings:

```bash
python run_agent_report.py \
  --report evaluation/datasets/juliet_v1_seed_report.json \
  --config configs/config.ndk.yaml \
  --output-dir data/experiments/juliet-react-specialized
```

Run the four initial ablation modes and generate a comparison automatically:

```bash
python run_seed_ablation.py \
  --report evaluation/datasets/juliet_v1_seed_report.json \
  --labels evaluation/datasets/juliet_v1_labels.json \
  --config configs/config.ndk.yaml \
  --compile-commands data/cache/juliet-compile-commands.json
```

The first completed local-model experiment is preserved in
`evaluation/results/juliet_cwe369_qwen3_ablation.json`. It uses 50 balanced
CWE-369 cases and should be treated as a single-CWE baseline. The default
`juliet_v1` dataset is sampled across multiple CWE categories for the next
generalization experiment.

## Ablation Protocol

Change one variable at a time:

| Run name | Context | Tools | Specialized prompt | Critic |
| --- | --- | --- | --- | --- |
| `direct-llm` | finding only | no | no | no |
| `context-only` | initial context | no | no | no |
| `react-tools` | initial context | yes | no | no |
| `react-specialized` | initial context | yes | yes | no |
| `controlled_workflow` | routed evidence | routed tools | yes | yes |

For fair comparisons, keep the dataset, model, temperature, token limit, and
source revision fixed. For model comparisons, keep the Agent workflow fixed.

Run every non-deterministic experiment multiple times and report mean and
standard deviation. Always report quality together with latency, tokens, and
estimated cost.

Controlled workflow runs additionally report budget exhaustion, Critic
execution, and Critic rejection rates.

## Commands

Prepare 50 diverse candidates from one or more real scan reports:

```bash
python evaluate.py prepare \
  data/reports/module-base.json \
  data/reports/module-kernel.json \
  --name gme-v1 \
  --limit 50 \
  --source-root /path/to/GME \
  --output evaluation/datasets/gme_v1_labels.json
```

Review every generated case and change `review_status` from `pending` to
`reviewed` only after filling `expected_verdict`, tools, evidence, and notes.
Pending cases are excluded from all metrics.

Run the four initial ablation variants:

```bash
python run_ablation.py /path/to/GME/module/base/src \
  --config config.yaml \
  --compile-commands /path/to/GME/build_base/compile_commands.json \
  --labels evaluation/datasets/gme_v1_labels.json \
  --price-per-million-tokens 2
```

Evaluate one run:

```bash
python evaluate.py run \
  --labels evaluation/datasets/example_labels.json \
  --report evaluation/examples/example_report.json \
  --name react-tools \
  --price-per-million-tokens 2 \
  --output data/evaluations/react-tools.json
```

Compare evaluated runs:

```bash
python evaluate.py compare \
  data/evaluations/direct-llm.json \
  data/evaluations/react-tools.json \
  data/evaluations/react-critic.json
```
