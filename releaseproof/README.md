# ReleaseProof

**CI-native pre-release safety assessment for Terraform plans and PostgreSQL migrations.**

ReleaseProof evaluates selected infrastructure and database changes *before*
release, identifies potentially destructive or incompatible operations, and
returns an explainable **Pass / Warning / Block / Analysis Incomplete** decision
inside GitHub. It runs in your existing GitHub Actions environment — no always-on
workers, no production credentials, no production database access.

This repository implements **Stage 1 (the CI-native MVP)** of the architecture.

---

## What it does

| Area | Behaviour |
| --- | --- |
| Trigger | Runs on pull-request create/update |
| Terraform analysis | Reads `terraform show -json` output, classifies planned actions, applies context-aware risk rules (prod vs disposable, stateful vs not) |
| Database analysis | Lints changed PostgreSQL migrations with built-in rules + [Squawk](https://github.com/sbdchd/squawk) when available |
| Decision | Deterministic Pass / Warning / Block / Analysis Incomplete |
| Integration | GitHub job summary + workflow exit status |
| Security | Analyses sensitive inputs inside CI; redacts findings; no prod credentials |
| Cost | Reuses your CI compute; nothing runs permanently |

### What it does **not** do
No `terraform apply` or rollback, no production DB connections, no Kubernetes
orchestration, no LLM-based risk decisions, no standalone dashboard. It detects
*selected* risks — it does not guarantee production behaviour or replace tested
recovery.

---

## Install

```bash
pip install .
# or, for development:
pip install -e ".[dev]"
```

Optional — full migration-lint coverage (Layer A):

```bash
pip install squawk-cli        # or: npm install -g squawk-cli
```

If Squawk is not installed, ReleaseProof runs its built-in migration rules and
notes the reduced coverage — the headline destructive patterns are still caught.
The Squawk JSON normaliser handles both the v1 and v2 reporter formats.

Optional — runtime validation (Layer B) needs a PostgreSQL driver:

```bash
pip install ".[runtime]"      # installs psycopg2-binary
```

---

## Usage

```bash
# Analyse a Terraform plan and changed migrations:
releaseproof \
  --plan plan.json \
  --migrations-from changed_files.txt \
  --migrations-dir migrations \
  --json-out releaseproof.json
```

Generate `plan.json` from your existing workflow:

```bash
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > plan.json   # keep this out of logs
```

### Exit codes (drive the GitHub check)

| Code | Decision | Meaning |
| --- | --- | --- |
| `0` | Pass / Warning | No blocking violations (warnings are non-blocking by default) |
| `1` | Block | A blocking rule was triggered |
| `2` | Analysis Incomplete | Input missing/invalid or an analyzer failed — **never a silent pass** |

### Key flags

| Flag | Purpose |
| --- | --- |
| `--plan PATH` | Terraform plan JSON |
| `--migration PATH` | A changed migration file (repeatable) |
| `--migrations-from FILE` | Newline-separated changed paths (e.g. a PR diff) |
| `--migrations-dir DIR` | Only treat `.sql` under this dir as migrations |
| `--policy PATH` | Custom policy YAML (defaults to the packaged policy) |
| `--no-squawk` | Built-in migration rules only |
| `--runtime-validate` | Enable Layer B (apply migrations to a disposable test DB) |
| `--test-dsn DSN` | libpq DSN for Layer B (or `RELEASEPROOF_TEST_DSN`) |
| `--baseline PATH` | SQL establishing a baseline schema inside the disposable schema before migrations (Layer B) |
| `--json-out PATH` | Also write the JSON report to a file |

### Layer B runtime validation

```bash
releaseproof \
  --runtime-validate \
  --test-dsn "host=localhost port=5432 user=postgres dbname=rp_test" \
  --baseline migrations/baseline.sql \
  --migration migrations/0042_add_index.sql
```

Each run creates a throwaway schema (`releaseproof_check`), applies the baseline
then the migrations **statement-by-statement under autocommit** (so
`CREATE INDEX CONCURRENTLY` works), captures any failure as a
`PG-RUNTIME-APPLY-FAILED` finding, and drops the schema afterwards — leaving the
test database clean. A clean apply does **not** prove safety under production
volume, locks, or concurrency; the report says so.

---

## GitHub Actions

A ready-to-use, PR-safe workflow is at
[`.github/workflows/releaseproof.yml`](.github/workflows/releaseproof.yml). It
uses `pull_request` (never `pull_request_target`), minimal token permissions,
and keeps the raw plan out of logs. Layer B runtime validation is included as a
commented-out `services: postgres` block.

---

## Policy

Decisions are driven by a **version-controlled YAML policy** — transparent,
reviewable, and deterministic. The packaged default lives at
[`src/releaseproof/config/defaults.yml`](src/releaseproof/config/defaults.yml).

```yaml
version: 1
policies:
  terraform:
    TF-DESTROY-PROD: block
    TF-REPLACE-STATEFUL: warn
  postgres:
    PG-DROP-TABLE: block
    PG-ADD-INDEX-NON-CONCURRENT: warn
  severity_defaults:      # fallback for unmapped (e.g. native Squawk) rules
    critical: block
    high: block
    medium: warn
  analysis:
    missing_terraform_plan: incomplete
    analyzer_error: incomplete
```

> **Policy integrity:** a pull request must not weaken the policy used to assess
> itself. Evaluate against the policy on the protected base branch, or require a
> protected approval for policy changes.

---

## Architecture (Stage 1)

```
PR ─▶ GitHub Actions ─▶ terraform show -json ─┐
                        changed migrations ───┤
                                              ▼
                                   ReleaseProof CLI
                        ┌──────────────┴───────────────┐
                 Terraform analyzer            Postgres analyzer
                 (classify + rules)        (Squawk + built-in rules)
                        └──────────────┬───────────────┘
                                normalised findings
                                       ▼
                          deterministic policy engine
                                       ▼
                     Pass / Warning / Block / Incomplete
                                       ▼
                     GitHub job summary + exit status
```

### Code layout

```
src/releaseproof/
├── cli/main.py                      # orchestration + exit status
├── inputs/
│   ├── terraform_plan.py            # validate + read plan JSON
│   └── migration_files.py           # read changed .sql migrations
├── analyzers/
│   ├── terraform/{parser,rules}.py  # classify actions, apply risk rules
│   └── postgres/
│       ├── builtin_rules.py         # product-specific migration checks
│       ├── squawk_runner.py         # Layer A static analysis
│       └── runtime_validator.py     # Layer B disposable-DB apply (gated)
├── findings/{models,normalize}.py   # shared finding model + redaction
├── policy/{loader,evaluator}.py     # versioned YAML + deterministic decision
├── reporters/{json_report,github_summary}.py
└── config/defaults.yml              # default policy
```

---

## Design commitments

- **CI-native** — runs where your code already builds; no idle compute.
- **Read-only** — analyses plans and migration files; never mutates production.
- **Deterministic** — rule-based, versioned policy; identical inputs → identical
  decision.
- **Fail visibly** — missing/malformed/incomplete inputs produce *Analysis
  Incomplete*, never a silent Pass.
- **Locality of sensitive data** — raw plans are parsed in CI; only minimal,
  redacted findings leave the process.
- **Reuse mature tools** — integrates Squawk rather than rebuilding a SQL linter.

---

## Rules

### Terraform
| Rule | Fires when |
| --- | --- |
| `TF-DESTROY-PROD` | delete/replace of a production-tagged resource |
| `TF-DELETE-STATEFUL` | delete of a stateful (db/disk/bucket) resource |
| `TF-REPLACE-STATEFUL` | replacement of a stateful resource |
| `TF-DELETE-GENERIC` | delete of any other resource |
| `TF-IAM-BROADEN` | create/modify of IAM / security-group / policy |
| `TF-UNSUPPORTED-FORMAT` | plan format version not supported → incomplete |

### PostgreSQL (built-in)
| Rule | Fires when |
| --- | --- |
| `PG-DROP-TABLE` / `PG-DROP-COLUMN` | destructive drops |
| `PG-TRUNCATE` | TRUNCATE in a migration |
| `PG-RENAME-TABLE` / `PG-RENAME-COLUMN` | non-backward-compatible renames |
| `PG-NOT-NULL-NO-DEFAULT` | add NOT NULL column without default |
| `PG-ADD-COLUMN-DEFAULT-VOLATILE` | volatile default → table rewrite |
| `PG-CHANGE-COLUMN-TYPE` | column type change |
| `PG-ADD-INDEX-NON-CONCURRENT` | index build without CONCURRENTLY |

Native Squawk rules surface as `PG-SQUAWK-<RULE>` and are handled by
`severity_defaults` unless mapped explicitly.

---

## Development

```bash
pip install -e ".[dev]"
pytest                       # run the suite
pytest --cov=releaseproof    # with coverage
```

---

## Status

Architecture proposal implemented as a working Stage 1 MVP. Security review,
tool-version compatibility, CI constraints, and real cost measurements should be
verified during implementation and customer testing. The hosted control plane
(Stage 2) is intentionally **not** built until customer feedback demonstrates a
need for it.
