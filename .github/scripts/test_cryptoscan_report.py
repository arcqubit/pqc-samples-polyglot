import contextlib
import copy
import io
import json
import unittest

from cryptoscan_report import display_json, validate_report


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.report = {
            "filesScanned": 1,
            "findings": [{"severity": 4}],
            "summary": {"totalFindings": 1, "bySeverity": {"CRITICAL": 1}},
        }

    def test_critical_findings_are_report_only(self):
        self.assertEqual(validate_report(self.report, 1), (1, 1, {
            "CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
        }))

    def test_clean_scan_with_no_findings_succeeds(self):
        self.report["findings"] = []
        self.report["summary"] = {"totalFindings": 0, "bySeverity": {}}
        self.assertEqual(validate_report(self.report, 0)[:2], (1, 0))

    def test_exit_one_without_critical_findings_fails(self):
        self.report["summary"]["bySeverity"] = {"HIGH": 1}
        with self.assertRaisesRegex(ValueError, "exit code"):
            validate_report(self.report, 1)

    def test_execution_error_fails_even_with_valid_report(self):
        with self.assertRaisesRegex(ValueError, "exit code"):
            validate_report(self.report, 2)

    def test_invalid_reports_fail(self):
        cases = [None, {}, {"findings": [], "summary": {}}]
        for field, value in (("filesScanned", 0), ("filesScanned", True)):
            report = copy.deepcopy(self.report)
            report[field] = value
            cases.append(report)
        for field, value in (("totalFindings", 2), ("bySeverity", {"HIGH": -1}),
                             ("bySeverity", {"CRITICAL": 0})):
            report = copy.deepcopy(self.report)
            report["summary"][field] = value
            cases.append(report)
        for report in cases:
            with self.subTest(report=report), self.assertRaises(ValueError):
                validate_report(report, 0)

    def test_report_content_cannot_create_workflow_commands(self):
        raw = json.dumps({"source": "::error::from scanned source"}, indent=2)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            display_json(raw)
        lines = output.getvalue().splitlines()
        self.assertEqual(lines[0], "::group::CryptoScan JSON results")
        token = lines[1].removeprefix("::stop-commands::")
        self.assertEqual("\n".join(lines[2:-2]), raw)
        self.assertEqual(lines[-2:], [f"::{token}::", "::endgroup::"])


if __name__ == "__main__":
    unittest.main()
