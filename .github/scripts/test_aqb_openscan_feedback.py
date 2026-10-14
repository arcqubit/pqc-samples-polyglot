import contextlib
import copy
import io
from pathlib import Path
import tempfile
import unittest

from aqb_openscan_feedback import (classify_findings, emit_annotations, github_links,
                                normalize_findings, render_html, render_markdown)


class FeedbackTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        (self.root / "src").mkdir()
        self.source = self.root / "src" / "crypto example.go"
        self.source.write_text("package main\nvar hash = md5.New()\n", encoding="utf-8")
        self.report = {
            "filesScanned": 1,
            "findings": [{"id": "HASH-MD5-001-2-0", "file": str(self.source),
                          "line": 2, "column": 1, "severity": 4, "confidence": "HIGH",
                          "context": "var hash = md5.New()", "type": "MD5",
                          "description": "Broken hash", "remediation": "Review and replace MD5"}],
            "summary": {"totalFindings": 1, "bySeverity": {"CRITICAL": 1}},
        }
        self.source_url, self.run_url = github_links("owner/repo", "a" * 40, "123")

    def test_line_shifts_and_whitespace_do_not_create_new_findings(self):
        baseline = normalize_findings(self.report, self.root)
        self.report["findings"][0].update(id="HASH-MD5-001-20-4", line=20,
                                           column=5, context="  var   hash = md5.New()  ")
        findings, removed = classify_findings(normalize_findings(self.report, self.root), baseline)
        self.assertEqual(findings[0]["state"], "Existing")
        self.assertEqual(removed, 0)

    def test_fingerprints_are_independent_of_checkout_root(self):
        baseline = normalize_findings(self.report, self.root)
        with tempfile.TemporaryDirectory() as directory:
            other_root = Path(directory)
            (other_root / "src").mkdir()
            other_source = other_root / "src" / self.source.name
            other_source.write_text(self.source.read_text(), encoding="utf-8")
            self.report["findings"][0]["file"] = str(other_source)
            findings, _ = classify_findings(normalize_findings(self.report, other_root), baseline)
            self.assertEqual(findings[0]["state"], "Existing")

    def test_duplicate_and_removed_occurrences_are_counted(self):
        baseline = normalize_findings(self.report, self.root)
        current = baseline + [dict(baseline[0], line=3)]
        findings, removed = classify_findings(current, baseline)
        self.assertEqual([f["state"] for f in findings], ["Existing", "New"])
        self.assertEqual(removed, 0)
        self.assertEqual(classify_findings([], baseline)[1], 1)

    def test_no_baseline_is_inventory_and_empty_baseline_is_new(self):
        current = normalize_findings(self.report, self.root)
        self.assertEqual(classify_findings(current)[0][0]["state"], "Inventory")
        self.assertEqual(classify_findings(current, [])[0][0]["state"], "New")

    def test_annotation_cap_confidence_and_existing_filter(self):
        finding = normalize_findings(self.report, self.root)[0]
        findings = [dict(finding, state="New", line=n) for n in range(1, 21)]
        findings += [dict(finding, state="Existing"),
                     dict(finding, state="New", confidence="MEDIUM"),
                     dict(finding, state="New", severity="INFO")]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            count = emit_annotations(findings)
        self.assertEqual(count, 10)
        self.assertEqual(len(output.getvalue().splitlines()), 10)
        self.assertTrue(all(line.startswith("::warning ") for line in output.getvalue().splitlines()))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(emit_annotations(findings[-3:]), 0)

    def test_scanned_content_cannot_inject_workflow_commands(self):
        finding = normalize_findings(self.report, self.root)[0]
        finding.update(state="New", file="src/a,b:c%.go", type="MD5\n::error::injected",
                       remediation="review\r\n::add-mask::secret")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            emit_annotations([finding])
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        self.assertIn("file=src/a%2Cb%3Ac%25.go", output.getvalue())
        self.assertIn("%0A::error::injected", output.getvalue())
        self.assertIn("%0D%0A::add-mask::secret", output.getvalue())

    def test_markdown_and_html_escape_scanned_content(self):
        self.report["findings"][0].update(type="<script>alert(1)</script> @everyone [x](https://bad)",
            context="<script>alert(2)</script>", remediation="</details><img src=x onerror=alert(3)>")
        findings, _ = classify_findings(normalize_findings(self.report, self.root))
        markdown = render_markdown(self.report, findings, self.source_url, self.run_url)
        page = render_html(self.report, findings, self.source_url)
        for output in (markdown, page):
            self.assertNotIn("<script>", output)
            self.assertNotIn("<img", output)
        self.assertNotIn("@everyone", markdown)
        self.assertNotIn("[x](https://bad)", markdown)
        self.assertNotIn("&&#", markdown)
        self.assertIn("&#64;everyone", markdown)
        self.assertIn("src/crypto%20example.go#L2", markdown)
        self.assertIn("src/crypto%20example.go#L2", page)

    def test_collapsed_summary_caps_inventory_but_html_keeps_every_finding(self):
        current = normalize_findings(self.report, self.root)
        findings, _ = classify_findings(current * 210)
        summary = render_markdown(self.report, findings, self.source_url, self.run_url)
        page = render_html(self.report, findings, self.source_url)
        self.assertIn("<details>", summary)
        self.assertIn("showing 200 of 210", summary)
        self.assertEqual(page.count("<details>"), 210)
        self.assertIn("not labelled new or fixed", summary)

    def test_clean_comparison_reports_disappeared_findings_without_claiming_secure(self):
        baseline = normalize_findings(self.report, self.root)
        self.report["findings"] = []
        self.report["summary"] = {"totalFindings": 0, "bySeverity": {}}
        findings, removed = classify_findings([], baseline)
        summary = render_markdown(self.report, findings, self.source_url, self.run_url,
                                  "commit abc", removed)
        self.assertIn("**1 no longer reported**", summary)
        self.assertIn("not a security or quantum-readiness certification", summary)

    def test_bad_paths_positions_and_severity_counts_fail(self):
        for field, value in (("file", str(self.root.parent / "outside.go")),
                             ("line", 0), ("column", True), ("severity", 5),
                             ("severity", 3), ("confidence", "CERTAIN")):
            report = copy.deepcopy(self.report)
            report["findings"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                normalize_findings(report, self.root)


if __name__ == "__main__":
    unittest.main()
