"""Tests for the SARIF → Finding adapter."""

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from sarif import sarif_to_findings, _sarif_severity

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


class TestSarifToFindings:
    def test_basic_parse(self, tmp_path):
        findings = sarif_to_findings(FIXTURES / "sample.sarif", tmp_path)
        assert len(findings) == 3

    def test_file_and_line(self, tmp_path):
        findings = sarif_to_findings(FIXTURES / "sample.sarif", tmp_path)
        by_rule = {f.rule_id: f for f in findings}
        assert by_rule["PY-SECRET-001"].file_path == "app.py"
        assert by_rule["PY-SECRET-001"].line_start == 10
        assert by_rule["PY-SQLI-001"].file_path == "db.py"
        assert by_rule["PY-SQLI-001"].line_start == 42
        assert by_rule["PY-SQLI-001"].line_end == 43

    def test_tool_name_as_scanner(self, tmp_path):
        findings = sarif_to_findings(FIXTURES / "sample.sarif", tmp_path)
        assert all(f.scanner == "trivy" for f in findings)

    def test_message_populated(self, tmp_path):
        findings = sarif_to_findings(FIXTURES / "sample.sarif", tmp_path)
        by_rule = {f.rule_id: f for f in findings}
        assert "API key" in by_rule["PY-SECRET-001"].rule_message

    def test_merged_rule_ids_initialized(self, tmp_path):
        findings = sarif_to_findings(FIXTURES / "sample.sarif", tmp_path)
        for f in findings:
            assert f.merged_rule_ids == [f.rule_id]

    def test_missing_uri_skipped(self, tmp_path):
        """Results without a physicalLocation URI are silently dropped."""
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "Test", "rules": []}},
                "results": [
                    {"ruleId": "X1", "level": "error", "message": {"text": "ok"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"},
                                                         "region": {"startLine": 1}}}]},
                    {"ruleId": "X2", "level": "error", "message": {"text": "no uri"},
                     "locations": [{"physicalLocation": {"region": {"startLine": 1}}}]},
                ],
            }],
        }
        sf = tmp_path / "test.sarif"
        sf.write_text(json.dumps(sarif))
        findings = sarif_to_findings(sf, tmp_path)
        assert len(findings) == 1
        assert findings[0].rule_id == "X1"

    def test_multi_run_combined(self, tmp_path):
        """Findings from multiple runs in one SARIF file are all returned."""
        sarif = {
            "version": "2.1.0",
            "runs": [
                {"tool": {"driver": {"name": "ToolA", "rules": []}},
                 "results": [{"ruleId": "A1", "level": "error", "message": {"text": "a"},
                              "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"},
                                                                   "region": {"startLine": 1}}}]}]},
                {"tool": {"driver": {"name": "ToolB", "rules": []}},
                 "results": [{"ruleId": "B1", "level": "warning", "message": {"text": "b"},
                              "locations": [{"physicalLocation": {"artifactLocation": {"uri": "b.py"},
                                                                   "region": {"startLine": 2}}}]}]},
            ],
        }
        sf = tmp_path / "multi.sarif"
        sf.write_text(json.dumps(sarif))
        findings = sarif_to_findings(sf, tmp_path)
        assert len(findings) == 2
        scanners = {f.scanner for f in findings}
        assert scanners == {"toola", "toolb"}


class TestSarifSeverity:
    def test_cvss_score_critical(self):
        assert _sarif_severity("warning", {"properties": {"security-severity": "9.5"}}) == "CRITICAL"

    def test_cvss_score_high(self):
        assert _sarif_severity("warning", {"properties": {"security-severity": "8.1"}}) == "HIGH"

    def test_cvss_score_medium(self):
        assert _sarif_severity("warning", {"properties": {"security-severity": "5.0"}}) == "MEDIUM"

    def test_cvss_score_low(self):
        assert _sarif_severity("error", {"properties": {"security-severity": "2.0"}}) == "LOW"

    def test_level_error_fallback(self):
        assert _sarif_severity("error", {}) == "HIGH"

    def test_level_warning_fallback(self):
        assert _sarif_severity("warning", {}) == "MEDIUM"

    def test_level_note_fallback(self):
        assert _sarif_severity("note", {}) == "LOW"

    def test_level_none_fallback(self):
        assert _sarif_severity("none", {}) == "INFO"

    def test_fixture_severities(self, tmp_path):
        """Verify the fixture's three findings get expected severities."""
        findings = sarif_to_findings(FIXTURES / "sample.sarif", tmp_path)
        by_rule = {f.rule_id: f for f in findings}
        assert by_rule["PY-SECRET-001"].severity == "HIGH"   # score 8.1
        assert by_rule["PY-SQLI-001"].severity == "HIGH"    # score 7.5
        assert by_rule["PY-INFO-001"].severity == "MEDIUM"  # level=warning, no score


class TestGithubCodeScanningAlias:
    def test_alias_recognized(self):
        """github-code-scanning and codeql should both be treated as the same scanner."""
        # We test this at the parser level — both keys should appear in the
        # canonical dispatch condition in triage.py.
        import triage
        import inspect
        source = inspect.getsource(triage.main)
        assert '"codeql" in scanners or "github-code-scanning" in scanners' in source


class TestChangedFilesFilter:
    def test_filter_to_changed_files(self, tmp_path):
        """Findings for files not in the changed set are dropped."""
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "Test", "rules": []}},
                "results": [
                    {"ruleId": "R1", "level": "error", "message": {"text": "in diff"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"},
                                                         "region": {"startLine": 10}}}]},
                    {"ruleId": "R2", "level": "error", "message": {"text": "not in diff"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "utils.py"},
                                                         "region": {"startLine": 5}}}]},
                ],
            }],
        }
        sf = tmp_path / "test.sarif"
        sf.write_text(json.dumps(sarif))

        findings = sarif_to_findings(sf, tmp_path)
        assert len(findings) == 2

        # Simulate baseline filter inline (mirrors triage.py logic)
        changed = {"app.py"}
        filtered = [
            f for f in findings
            if f.file_path in changed
            or pathlib.Path(f.file_path).name in {pathlib.Path(c).name for c in changed}
        ]
        assert len(filtered) == 1
        assert filtered[0].rule_id == "R1"
