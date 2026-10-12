import copy
from pathlib import Path
import tempfile
import unittest

from cryptoscan_sarif import prepare_sarif


class SarifTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        (self.root / "src").mkdir()
        self.source = self.root / "src" / "crypto example.go"
        self.source.write_text("package main\n// finding\n")
        ids = ("HASH-MD5-001-1-0", "HASH-MD5-001-2-0")
        self.report = {
            "filesScanned": 1,
            "findings": [{"id": key, "file": str(self.source), "line": line, "column": 1}
                         for line, key in enumerate(ids, 1)],
            "summary": {"totalFindings": 2, "bySeverity": {"CRITICAL": 2}},
        }
        self.sarif = {"version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "CryptoScan", "rules": [
                {"id": key, "name": "MD5", "shortDescription": {"text": "Weak hash"}}
                for key in ids]}},
            "results": [{"ruleId": key, "level": "error", "message": {"text": "MD5"},
                         "locations": [{"physicalLocation": {
                             "artifactLocation": {"uri": str(self.source)},
                             "region": {"startLine": line, "startColumn": 1}}}]}
                        for line, key in enumerate(ids, 1)],
        }]}

    def test_stable_rules_and_source_links_preserve_all_results(self):
        original = copy.deepcopy(self.sarif)
        data = prepare_sarif(self.sarif, self.report, self.root, 1)
        run = data["runs"][0]
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 1)
        self.assertEqual(len(run["results"]), 2)
        for result in run["results"]:
            self.assertEqual(result["ruleId"], "HASH-MD5-001")
            self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                             "src/crypto%20example.go")
            self.assertIn("cryptoscanOccurrenceId", result["properties"])
        self.assertEqual(self.sarif, original)

    def test_dependency_rule_id_is_preserved(self):
        self.report["findings"][0]["id"] = "DEP-circl-go.mod"
        run = self.sarif["runs"][0]
        run["results"][0]["ruleId"] = "DEP-circl-go.mod"
        run["tool"]["driver"]["rules"][0]["id"] = "DEP-circl-go.mod"
        data = prepare_sarif(self.sarif, self.report, self.root, 1)
        self.assertEqual(data["runs"][0]["results"][0]["ruleId"], "DEP-circl-go.mod")

    def test_clean_scan_converts_null_results_and_rules_to_arrays(self):
        self.report["findings"] = []
        self.report["summary"] = {"totalFindings": 0, "bySeverity": {}}
        run = self.sarif["runs"][0]
        run["results"] = None
        run["tool"]["driver"]["rules"] = None
        data = prepare_sarif(self.sarif, self.report, self.root, 0)
        self.assertEqual(data["runs"][0]["results"], [])
        self.assertEqual(data["runs"][0]["tool"]["driver"]["rules"], [])

    def test_report_count_or_location_mismatch_fails(self):
        for change in ("count", "line", "unknown rule"):
            sarif = copy.deepcopy(self.sarif)
            run = sarif["runs"][0]
            if change == "count":
                run["results"].pop()
            elif change == "line":
                run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] = 99
            else:
                run["results"][0]["ruleId"] = "UNKNOWN-1-0"
            with self.subTest(change=change), self.assertRaises(ValueError):
                prepare_sarif(sarif, self.report, self.root, 1)

    def test_outside_repository_and_missing_files_fail(self):
        for source in (str(self.root.parent / "outside.go"), str(self.root / "missing.go")):
            sarif = copy.deepcopy(self.sarif)
            sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = source
            with self.subTest(source=source), self.assertRaises(ValueError):
                prepare_sarif(sarif, self.report, self.root, 1)

    def test_conflicting_stable_rule_definitions_fail(self):
        self.sarif["runs"][0]["tool"]["driver"]["rules"][1]["name"] = "Different algorithm"
        with self.assertRaisesRegex(ValueError, "Conflicting"):
            prepare_sarif(self.sarif, self.report, self.root, 1)

    def test_contextual_severities_keep_result_levels_and_highest_default(self):
        run = self.sarif["runs"][0]
        run["tool"]["driver"]["rules"][0]["defaultConfiguration"] = {"level": "error"}
        run["tool"]["driver"]["rules"][1]["defaultConfiguration"] = {"level": "warning"}
        run["results"][1]["level"] = "warning"
        data = prepare_sarif(self.sarif, self.report, self.root, 1)
        normalized = data["runs"][0]
        self.assertEqual(normalized["tool"]["driver"]["rules"][0]["defaultConfiguration"],
                         {"level": "error"})
        self.assertEqual([result["level"] for result in normalized["results"]], ["error", "warning"])

    def test_scanner_execution_error_fails(self):
        with self.assertRaisesRegex(ValueError, "exit code"):
            prepare_sarif(self.sarif, self.report, self.root, 2)


if __name__ == "__main__":
    unittest.main()
