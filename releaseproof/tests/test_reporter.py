"""Tests for reporters and the end-to-end CLI run."""
import json

from releaseproof.cli.main import main
from releaseproof.findings.models import Decision, Severity, Source
from releaseproof.findings.normalize import make_finding
from releaseproof.policy.evaluator import evaluate
from releaseproof.policy.loader import load_policy
from releaseproof.reporters import github_summary, json_report


def _ev(rule_ids_with_severity):
    findings = [
        make_finding(
            rule_id=rid,
            source=Source.POSTGRES,
            severity=sev,
            location="file.sql",
            observation="did a thing",
            reason="because",
            recommendation="do this",
        )
        for rid, sev in rule_ids_with_severity
    ]
    return evaluate(findings, load_policy())


def test_json_report_shape():
    ev = _ev([("PG-DROP-TABLE", Severity.CRITICAL)])
    report = json_report.build_report(ev)
    assert report["decision"] == "block"
    assert report["exit_code"] == 1
    assert report["summary"]["blocking"] == 1
    assert report["findings"][0]["rule_id"] == "PG-DROP-TABLE"
    assert report["findings"][0]["action"] == "block"


def test_json_report_is_valid_json():
    ev = _ev([("PG-ADD-INDEX-NON-CONCURRENT", Severity.MEDIUM)])
    text = json_report.render(ev)
    parsed = json.loads(text)  # must not raise
    assert parsed["decision"] == "warning"


def test_github_summary_contains_decision_and_table():
    ev = _ev([("PG-DROP-TABLE", Severity.CRITICAL)])
    md = github_summary.render(ev)
    assert "Block" in md
    assert "PG-DROP-TABLE" in md
    assert "| Decision |" in md  # table header


def test_github_summary_incomplete_is_not_pass():
    ev = evaluate([], load_policy(), incomplete_reasons=["missing_terraform_plan"])
    md = github_summary.render(ev)
    assert "Analysis Incomplete" in md
    assert "not** a" in md  # the "this is not a pass" explainer


def test_redaction_keeps_secrets_out_of_report():
    f = make_finding(
        rule_id="RP-X",
        source=Source.SYSTEM,
        severity=Severity.HIGH,
        location="file.sql",
        observation="ok",
        reason="ok",
        recommendation="ok",
        evidence={"password": "hunter2", "note": "connection to db with secret token"},
    )
    ev = evaluate([f], load_policy())
    text = json_report.render(ev)
    assert "hunter2" not in text
    assert "<redacted>" in text


# --- End-to-end CLI --------------------------------------------------------


def test_cli_safe_case_exits_zero(tf_fixtures, pg_fixtures, capsys):
    # --no-squawk keeps this deterministic: it asserts the built-in safe path,
    # independent of whether the stricter Squawk binary is installed.
    code = main(
        [
            "--plan",
            str(tf_fixtures / "safe_plan.json"),
            "--migration",
            str(pg_fixtures / "safe_migration.sql"),
            "--migrations-dir",
            str(pg_fixtures),
            "--no-squawk",
        ]
    )
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["decision"] == "pass"


def test_cli_unsafe_case_blocks(tf_fixtures, pg_fixtures, capsys):
    code = main(
        [
            "--plan",
            str(tf_fixtures / "unsafe_plan.json"),
            "--migration",
            str(pg_fixtures / "unsafe_mixed.sql"),
            "--migrations-dir",
            str(pg_fixtures),
        ]
    )
    assert code == 1
    out = json.loads(capsys.readouterr().out)
    assert out["decision"] == "block"
    assert out["summary"]["blocking"] >= 1


def test_cli_malformed_plan_is_incomplete(tf_fixtures, capsys):
    code = main(["--plan", str(tf_fixtures / "malformed_plan.json")])
    assert code == 2
    out = json.loads(capsys.readouterr().out)
    assert out["decision"] == "incomplete"


def test_cli_missing_plan_file_is_incomplete(tf_fixtures, capsys):
    code = main(["--plan", str(tf_fixtures / "nope.json")])
    assert code == 2
    out = json.loads(capsys.readouterr().out)
    assert out["decision"] == "incomplete"


def test_cli_json_out_written(tf_fixtures, pg_fixtures, tmp_path, capsys):
    out_path = tmp_path / "report.json"
    main(
        [
            "--plan",
            str(tf_fixtures / "safe_plan.json"),
            "--migration",
            str(pg_fixtures / "safe_migration.sql"),
            "--migrations-dir",
            str(pg_fixtures),
            "--json-out",
            str(out_path),
            "--no-squawk",
        ]
    )
    assert out_path.exists()
    saved = json.loads(out_path.read_text())
    assert saved["decision"] == "pass"


def test_cli_github_step_summary_written(tf_fixtures, pg_fixtures, tmp_path, monkeypatch, capsys):
    summary_file = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))
    main(
        [
            "--plan",
            str(tf_fixtures / "unsafe_plan.json"),
            "--migration",
            str(pg_fixtures / "unsafe_mixed.sql"),
            "--migrations-dir",
            str(pg_fixtures),
        ]
    )
    assert summary_file.exists()
    content = summary_file.read_text()
    assert "ReleaseProof" in content and "Block" in content
