"""ReleaseProof CLI — orchestrates a single pre-release assessment run.

Flow (doc section 5):
  inputs -> terraform analyzer + postgres analyzer -> normalised findings
         -> deterministic policy -> GitHub summary + JSON report + exit status

Design commitments honoured here:
  * Fail visibly: missing/invalid inputs become "Analysis Incomplete", never Pass.
  * Read-only: we only read plan JSON and migration files.
  * Locality of sensitive data: raw plan never leaves the process; only redacted
    findings reach the reports.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .. import __version__
from ..analyzers.postgres import runtime_validator, squawk_runner
from ..analyzers.terraform import rules as tf_rules
from ..analyzers.terraform.rules import TerraformRuleConfig
from ..findings.models import AnalyzerResult, Severity, Source
from ..findings.normalize import make_finding
from ..inputs.migration_files import MigrationInputError, collect_migrations
from ..inputs.terraform_plan import PlanInputError, load_plan
from ..policy.evaluator import evaluate
from ..policy.loader import Policy, PolicyError, load_policy
from ..reporters import github_summary, json_report


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="releaseproof",
        description="Pre-release safety assessment for Terraform plans and "
        "PostgreSQL migrations.",
    )
    p.add_argument("--plan", help="Path to Terraform plan JSON (terraform show -json).")
    p.add_argument(
        "--migration",
        action="append",
        default=[],
        dest="migrations",
        help="Path to a changed migration file. Repeatable.",
    )
    p.add_argument(
        "--migrations-from",
        help="File containing newline-separated changed file paths (e.g. PR diff).",
    )
    p.add_argument(
        "--migrations-dir",
        help="Only treat .sql files under this directory as migrations.",
    )
    p.add_argument("--policy", help="Path to a policy YAML (defaults to packaged policy).")
    p.add_argument(
        "--json-out",
        help="Write the JSON report to this path (also printed to stdout).",
    )
    p.add_argument(
        "--no-squawk",
        action="store_true",
        help="Disable the Squawk engine; use built-in migration rules only.",
    )
    p.add_argument(
        "--runtime-validate",
        action="store_true",
        help="Enable Layer B: apply migrations to a disposable test DB.",
    )
    p.add_argument(
        "--test-dsn",
        help="libpq DSN for the disposable test DB (or RELEASEPROOF_TEST_DSN).",
    )
    p.add_argument(
        "--baseline",
        help="SQL file establishing a representative baseline schema, applied "
        "inside the disposable schema before migrations (Layer B).",
    )
    p.add_argument("--version", action="version", version=f"releaseproof {__version__}")
    return p


def _read_changed_files(args: argparse.Namespace) -> list[str]:
    files = list(args.migrations)
    if args.migrations_from:
        path = Path(args.migrations_from)
        if path.exists():
            files.extend(
                line.strip()
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            )
    return files


def run(args: argparse.Namespace) -> int:
    """Execute a run and return the process exit code."""
    combined = AnalyzerResult()
    notes: list[str] = []

    # --- Load policy (a broken policy is an analyzer error → Incomplete) -------
    try:
        policy: Policy = load_policy(args.policy)
    except PolicyError as exc:
        combined.completed = False
        combined.incomplete_reasons.append("analyzer_error")
        combined.findings.append(
            make_finding(
                rule_id="RP-POLICY-ERROR",
                source=Source.SYSTEM,
                severity=Severity.HIGH,
                location=str(args.policy or "<packaged defaults>"),
                observation="Policy file could not be loaded",
                reason=str(exc),
                recommendation="Fix the policy YAML and re-run.",
            )
        )
        return _finish(combined, policy=None, notes=notes, args=args)

    tf_config = TerraformRuleConfig(
        stateful_resource_types=policy.stateful_resource_types
        or TerraformRuleConfig().stateful_resource_types,
        production_markers=policy.production_markers
        or TerraformRuleConfig().production_markers,
    )

    # --- Terraform analysis ----------------------------------------------------
    if args.plan:
        try:
            plan = load_plan(args.plan)
            combined.extend(
                tf_rules.analyze(
                    plan.resource_changes,
                    config=tf_config,
                    format_supported=plan.format_supported,
                    format_version=plan.format_version,
                )
            )
        except PlanInputError as exc:
            combined.completed = False
            combined.incomplete_reasons.append(exc.reason_code)
            combined.findings.append(
                make_finding(
                    rule_id="RP-TF-INPUT",
                    source=Source.SYSTEM,
                    severity=Severity.HIGH,
                    location=str(args.plan),
                    observation="Terraform plan could not be analysed",
                    reason=str(exc),
                    recommendation="Provide valid `terraform show -json` output.",
                )
            )
    else:
        # No plan supplied at all. Mapped through policy (default: incomplete).
        combined.incomplete_reasons.append("missing_terraform_plan")
        notes.append("No Terraform plan provided (--plan).")

    # --- PostgreSQL analysis ---------------------------------------------------
    changed = _read_changed_files(args)
    try:
        migrations = collect_migrations(
            changed, migrations_dir=args.migrations_dir
        )
    except MigrationInputError as exc:
        migrations = []
        combined.completed = False
        combined.incomplete_reasons.append(exc.reason_code)
        combined.findings.append(
            make_finding(
                rule_id="RP-PG-INPUT",
                source=Source.SYSTEM,
                severity=Severity.HIGH,
                location="<migrations>",
                observation="A migration file could not be read",
                reason=str(exc),
                recommendation="Ensure changed migration paths are readable in CI.",
            )
        )

    if migrations:
        combined.extend(squawk_runner.run(migrations, use_squawk=not args.no_squawk))
        if args.runtime_validate:
            baseline_sql = None
            if args.baseline:
                baseline_path = Path(args.baseline)
                if baseline_path.exists():
                    baseline_sql = baseline_path.read_text(encoding="utf-8")
                else:
                    notes.append(f"Baseline SQL file not found: {args.baseline}")
            combined.extend(
                runtime_validator.run(
                    migrations,
                    dsn=args.test_dsn,
                    enabled=True,
                    baseline_sql=baseline_sql,
                )
            )
    elif not changed:
        combined.incomplete_reasons.append("missing_migrations")
        notes.append("No migration files changed.")

    notes.extend(combined.notes)
    return _finish(combined, policy=policy, notes=notes, args=args)


def _finish(
    combined: AnalyzerResult,
    *,
    policy: Policy | None,
    notes: list[str],
    args: argparse.Namespace,
) -> int:
    # If the policy itself failed to load, fall back to a built-in default so we
    # can still emit an Incomplete report rather than crash.
    if policy is None:
        policy = load_policy()  # packaged defaults always load

    evaluation = evaluate(
        combined.findings,
        policy,
        incomplete_reasons=combined.incomplete_reasons,
    )

    # JSON report (stdout + optional file).
    json_text = json_report.render(evaluation, notes=notes)
    print(json_text)
    if args.json_out:
        Path(args.json_out).write_text(json_text + "\n", encoding="utf-8")

    # GitHub step summary.
    md = github_summary.render(evaluation, notes=notes)
    wrote = github_summary.write_step_summary(md)
    if not wrote:
        # Local run: print the human summary to stderr so stdout stays clean JSON.
        print("\n" + md, file=sys.stderr)

    return evaluation.exit_code


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    return run(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
