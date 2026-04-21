"""Core unit tests for arbiter triage logic."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from triage import Finding, Verdict, dedupe_findings


def _finding(file="app.py", start=10, end=10, rule="test/rule", sev="HIGH"):
    return Finding(
        rule_id=rule,
        rule_message="test message",
        severity=sev,
        file_path=file,
        line_start=start,
        line_end=end,
        code_context="10  x = input()",
        language="python",
        merged_rule_ids=[rule],
    )


class TestDedupFindings:
    def test_no_duplicates_unchanged(self):
        findings = [_finding(start=10), _finding(start=20)]
        assert len(dedupe_findings(findings)) == 2

    def test_same_location_collapsed(self):
        f1 = _finding(rule="rule-a", sev="HIGH")
        f2 = _finding(rule="rule-b", sev="MEDIUM")
        result = dedupe_findings([f1, f2])
        assert len(result) == 1
        assert result[0].rule_id == "rule-a"  # higher severity wins
        assert "rule-b" in result[0].merged_rule_ids

    def test_higher_severity_promoted(self):
        low = _finding(rule="low-rule", sev="LOW")
        critical = _finding(rule="crit-rule", sev="CRITICAL")
        result = dedupe_findings([low, critical])
        assert result[0].rule_id == "crit-rule"

    def test_different_files_not_merged(self):
        f1 = _finding(file="a.py")
        f2 = _finding(file="b.py")
        assert len(dedupe_findings([f1, f2])) == 2


class TestVerdictEffectiveSeverity:
    def test_uses_adjusted_when_present(self):
        v = Verdict(
            verdict="true_positive", confidence=0.9,
            severity="high", reasoning="",
            suggested_fix_sketch=None,
            adjusted_severity="low",
        )
        assert v.effective_severity == "low"

    def test_falls_back_to_severity(self):
        v = Verdict(
            verdict="true_positive", confidence=0.9,
            severity="high", reasoning="",
            suggested_fix_sketch=None,
        )
        assert v.effective_severity == "high"


class TestFindingFromCodeql:
    def test_basic_mapping(self):
        from triage import finding_from_codeql
        alert = {
            "number": 7,
            "html_url": "https://github.com/org/repo/security/code-scanning/7",
            "rule": {
                "id": "py/sql-injection",
                "security_severity_level": "high",
                "description": "SQL injection",
            },
            "most_recent_instance": {
                "location": {"path": "app.py", "start_line": 42, "end_line": 42},
                "message": {"text": "Unsanitized input flows to query"},
            },
        }
        f = finding_from_codeql(alert, pathlib.Path("/repo"))
        assert f.rule_id == "py/sql-injection"
        assert f.codeql_alert_number == 7
        assert f.scanner == "codeql"
        assert f.line_start == 42
        assert f.severity == "HIGH"


class TestReachabilityHelpers:
    def test_containing_function_basic(self, tmp_path):
        from reachability import containing_function
        src = tmp_path / "app.py"
        src.write_text(
            "def process(data):\n"
            "    result = eval(data)\n"
            "    return result\n"
        )
        name, line = containing_function(src, 2)
        assert name == "process"
        assert line == 1

    def test_module_scope_returns_none(self, tmp_path):
        from reachability import containing_function
        src = tmp_path / "config.py"
        src.write_text("DEBUG = True\n")
        assert containing_function(src, 1) is None
