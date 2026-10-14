"""Publish useful AQB OpenScan feedback without requiring GitHub Code Security."""

import argparse
from collections import Counter
import hashlib
import html
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import quote

from aqb_openscan_report import SEVERITIES, validate_report
from aqb_openscan_sarif import repository_path


SEVERITY_NAMES = tuple(reversed(SEVERITIES))
ANNOTATION_LIMIT = 10
DETAIL_LIMIT = 10
INVENTORY_LIMIT = 200


def normalize_findings(report, root):
    # Feedback runs only after the scanner's exit status has been checked. Still
    # validate the report independently, including the per-finding counts below.
    validate_report(report, 0)
    root = Path(root).resolve()
    findings = []
    for finding in report["findings"]:
        severity = finding.get("severity")
        if type(severity) is not int or severity not in range(5):
            raise ValueError("Finding has an invalid severity")
        line, column = finding.get("line"), finding.get("column", 1)
        if type(line) is not int or line < 1 or type(column) is not int or column < 1:
            raise ValueError("Finding has an invalid source position")
        occurrence = finding.get("id")
        if not isinstance(occurrence, str) or not occurrence:
            raise ValueError("Finding is missing a rule ID")
        source = repository_path(finding.get("file"), root)
        rule = re.sub(r"-\d+-\d+$", "", occurrence)
        confidence = finding.get("confidence", "UNKNOWN")
        if confidence not in ("HIGH", "MEDIUM", "LOW", "UNKNOWN"):
            raise ValueError("Finding has an invalid confidence")
        context = finding.get("context") or finding.get("match", "")
        if not isinstance(context, str):
            raise ValueError("Finding context must be text")
        # Ignore line/column shifts and whitespace. Count duplicate fingerprints
        # separately so an additional occurrence is still detected as new.
        identity = [rule, source, " ".join(context.split())]
        fingerprint = hashlib.sha256(json.dumps(identity).encode()).hexdigest()
        entry = {
            "rule": rule, "file": source, "line": line, "column": column,
            "severity": SEVERITY_NAMES[severity], "confidence": confidence,
            "fingerprint": fingerprint, "context": context,
        }
        for field in ("type", "description", "remediation"):
            value = finding.get(field, "")
            if not isinstance(value, str):
                raise ValueError(f"Finding {field} must be text")
            entry[field] = value
        findings.append(entry)
    actual = Counter(f["severity"] for f in findings)
    expected = report["summary"]["bySeverity"]
    if any(actual[s] != expected.get(s, 0) for s in SEVERITIES):
        raise ValueError("Per-finding severities do not match the summary")
    return findings


def classify_findings(findings, baseline=None):
    remaining = Counter(f["fingerprint"] for f in baseline or [])
    classified = []
    for finding in findings:
        finding = dict(finding)
        if baseline is None:
            finding["state"] = "Inventory"
        elif remaining[finding["fingerprint"]]:
            finding["state"] = "Existing"
            remaining[finding["fingerprint"]] -= 1
        else:
            finding["state"] = "New"
        classified.append(finding)
    return classified, sum(remaining.values())


def actionable(finding):
    return finding["confidence"] == "HIGH" and finding["severity"] in SEVERITIES[:3]


def priority(finding):
    return (finding["state"] == "Existing", not actionable(finding),
            SEVERITIES.index(finding["severity"]),
            ("HIGH", "MEDIUM", "LOW", "UNKNOWN").index(finding["confidence"]),
            finding["file"], finding["line"], finding["column"], finding["rule"])


def markdown_text(value, limit=600):
    text = " ".join(str(value).split())
    if len(text) > limit:
        text = text[:limit - 1] + "…"
    # Treat scanned content as text, including Markdown and mention syntax.
    return "".join(f"&#{ord(character)};" if character in "\\`*_{}[]()#+!|@"
                   else html.escape(character, quote=True) for character in text)


def github_links(repository, commit, run_id, server="https://github.com"):
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repository):
        raise ValueError("Invalid GitHub repository")
    if not re.fullmatch(r"[0-9a-f]{40,64}", commit):
        raise ValueError("Invalid source commit")
    if not run_id.isdigit() or not re.fullmatch(r"https://[\w.:-]+", server):
        raise ValueError("Invalid GitHub run URL")
    repo_url = f"{server}/{repository}"
    return f"{repo_url}/blob/{commit}/", f"{repo_url}/actions/runs/{run_id}"


def source_link(finding, source_url):
    return f"{source_url}{quote(finding['file'], safe='/')}#L{finding['line']}"


def render_markdown(report, findings, source_url, run_url, baseline_label=None,
                    removed=0):
    states = Counter(f["state"] for f in findings)
    ordered = sorted(findings, key=priority)
    candidate_count = sum(actionable(f) for f in findings)
    lines = ["## AQB OpenScan", "",
              f"Scanned **{report['filesScanned']} files** in the polyglot repository: "
              f"**{len(findings)} findings**, including **{candidate_count} "
              "high-confidence findings at medium severity or above**.", ""]
    if baseline_label:
        lines += [f"Compared with {markdown_text(baseline_label)}: "
                  f"**{states['New']} new**, **{states['Existing']} existing**, "
                  f"**{removed} no longer reported**.", ""]
    else:
        lines += ["**Inventory scan:** no comparison baseline was available. "
                  "Findings are not labelled new or fixed.", ""]
    lines += ["| Severity | Total |" + (" New | Existing |" if baseline_label else ""),
              "| --- | ---: |" + (" ---: | ---: |" if baseline_label else "")]
    for severity in SEVERITIES:
        matching = [f for f in findings if f["severity"] == severity]
        row = f"| {severity.title()} | {len(matching)} |"
        if baseline_label:
            row += (f" {sum(f['state'] == 'New' for f in matching)} |"
                    f" {sum(f['state'] == 'Existing' for f in matching)} |")
        lines.append(row)
    lines += ["", "Report only: findings do not fail this sample pipeline. Pattern matches need "
              "contextual review; confidence is the scanner's estimate. Coverage and "
              "finding counts are not a security or quantum-readiness certification.", "",
              f"[Open this Actions run and download reports]({run_url}#artifacts): "
              "**aqb-openscan-polyglot-report** contains JSON, SARIF, and a browsable "
              "`polyglot-findings.html` report, retained for seven days. "
              "GitHub Code Security is not required for this report.", ""]
    annotation_count = min(ANNOTATION_LIMIT, sum(actionable(f) and f['state'] != 'Existing'
                                               for f in findings))
    lines += [f"**{annotation_count} prioritized source annotations** published as warnings "
              "(maximum ten; high confidence, medium severity or above; new findings "
              "only when a baseline exists). PR diff visibility depends on changed lines "
              "and GitHub's permissions; full reports remain available.", ""]
    if ordered:
        lines += ["<details>", f"<summary>Review prioritized findings "
                  f"(showing {min(DETAIL_LIMIT, len(ordered))} of {len(ordered)})</summary>", ""]
        for finding in ordered[:DETAIL_LIMIT]:
            label = f"{finding['file']}:{finding['line']}"
            lines += [f"**{finding['severity'].title()} · {finding['confidence'].title()} "
                      f"confidence · {finding['state']}** — "
                      f"{markdown_text(finding['type'], 160)}", "",
                      f"[{markdown_text(label, 300)}]({source_link(finding, source_url)}) "
                      f"· Rule: {markdown_text(finding['rule'], 100)}", "",
                      markdown_text(finding['description'], 400), "",
                      "Suggested next step: " + markdown_text(
                          finding['remediation'] or "Review the code and confirm whether "
                          "the detected usage is relevant.", 600), ""]
        lines += ["</details>", ""]
    if ordered:
        lines += ["<details>", f"<summary>Finding inventory "
                  f"(showing {min(INVENTORY_LIMIT, len(ordered))} of {len(ordered)})</summary>", "",
                  "| State | Severity | Confidence | Finding | Source |",
                  "| --- | --- | --- | --- | --- |"]
        for finding in ordered[:INVENTORY_LIMIT]:
            lines.append(f"| {finding['state']} | {finding['severity'].title()} | "
                         f"{finding['confidence'].title()} | "
                         f"{markdown_text(finding['type'], 160)} | "
                         f"[{markdown_text(finding['file'], 300)}:{finding['line']}]"
                         f"({source_link(finding, source_url)}) |")
        lines += ["", "The HTML, JSON, and SARIF artifacts retain the complete inventory.",
                  "", "</details>", ""]
    return "\n".join(lines)


def render_html(report, findings, source_url, baseline_label=None, removed=0):
    states = Counter(f["state"] for f in findings)
    comparison = (f"Compared with {html.escape(baseline_label)}: {states['New']} new, "
                  f"{states['Existing']} existing, {removed} no longer reported."
                  if baseline_label else "Inventory scan; no comparison baseline available.")
    parts = ["<!doctype html><html lang='en'><meta charset='utf-8'>",
             "<meta name='viewport' content='width=device-width, initial-scale=1'>",
             "<title>AQB OpenScan report</title><style>body{font:16px system-ui;max-width:1100px;"
             "margin:40px auto;padding:0 20px;color:#18212c}details{border:1px solid #ccd3db;"
             "border-radius:6px;padding:12px;margin:12px 0}summary{cursor:pointer}"
             "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f4f8;padding:12px}"
             "a{color:#075da8}p{line-height:1.5}</style><body><h1>AQB OpenScan</h1>",
             f"<p>Scanned <strong>{report['filesScanned']} files</strong> in the polyglot repository: "
             f"<strong>{len(findings)} findings</strong>.</p><p>{comparison}</p>",
             "<p>Report only. Pattern matches require contextual review. This inventory "
             "does not certify security or quantum readiness.</p>",
             "<p>Original reports: <a href='polyglot-findings.json'>JSON</a> · "
             "<a href='polyglot-findings.sarif'>SARIF</a></p>"]
    for finding in sorted(findings, key=priority):
        parts += ["<details><summary>" + html.escape(
            f"{finding['state']} · {finding['severity'].title()} · "
            f"{finding['confidence'].title()} confidence · {finding['type']} · "
            f"{finding['file']}:{finding['line']}") + "</summary>",
            f"<p><a href='{html.escape(source_link(finding, source_url), quote=True)}'>"
            "Open source at the scanned commit</a></p>",
            f"<p>Rule: {html.escape(finding['rule'])}</p>",
            f"<p>{html.escape(finding['description'])}</p>",
            f"<pre>{html.escape(finding['context'])}</pre>",
            f"<p><strong>Suggested next step:</strong> "
            f"{html.escape(finding['remediation'])}</p></details>"]
    return "\n".join(parts + ["</body></html>"])


def command_escape(value, property_value=False):
    value = str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if property_value:
        value = value.replace(":", "%3A").replace(",", "%2C")
    return value


def emit_annotations(findings):
    selected = [f for f in sorted(findings, key=priority)
                if actionable(f) and f["state"] != "Existing"][:ANNOTATION_LIMIT]
    for finding in selected:
        message = (f"{finding['type']} ({finding['confidence'].lower()} confidence). "
                   f"Review in context. {finding['remediation']}")[:1000]
        title = f"AQB OpenScan: {finding['severity'].title()} / {finding['rule']}"
        print(f"::warning file={command_escape(finding['file'], True)},"
              f"line={finding['line']},col={finding['column']},"
              f"title={command_escape(title, True)}::{command_escape(message)}", flush=True)
    return len(selected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report")
    parser.add_argument("root")
    parser.add_argument("--baseline-report")
    parser.add_argument("--baseline-root")
    parser.add_argument("--baseline-sha")
    args = parser.parse_args()
    try:
        path = Path(args.report)
        report = json.loads(path.read_text(encoding="utf-8"))
        findings = normalize_findings(report, args.root)
        baseline, label = None, None
        if args.baseline_report:
            if not args.baseline_root or not args.baseline_sha:
                raise ValueError("Baseline requires its source root and commit")
            baseline = normalize_findings(json.loads(Path(args.baseline_report).read_text(
                encoding="utf-8")), args.baseline_root)
            label = f"commit {args.baseline_sha[:12]}"
        findings, removed = classify_findings(findings, baseline)
        source_url, run_url = github_links(os.environ["GITHUB_REPOSITORY"],
            os.environ["AQB_OPENSCAN_HEAD_SHA"], os.environ["GITHUB_RUN_ID"],
            os.environ.get("GITHUB_SERVER_URL", "https://github.com"))
        source_repository = os.environ.get("AQB_OPENSCAN_SOURCE_REPOSITORY")
        if source_repository:
            source_url, _ = github_links(source_repository,
                os.environ["AQB_OPENSCAN_HEAD_SHA"], os.environ["GITHUB_RUN_ID"],
                os.environ.get("GITHUB_SERVER_URL", "https://github.com"))
        summary = render_markdown(report, findings, source_url, run_url, label, removed)
        if len(summary.encode()) > 900_000:
            raise ValueError("Feedback exceeds GitHub size limits")
        path.with_suffix(".md").write_text(summary, encoding="utf-8")
        path.with_suffix(".html").write_text(render_html(
            report, findings, source_url, label, removed), encoding="utf-8")
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as output:
            output.write(summary)
        count = emit_annotations(findings)
        print(f"AQB OpenScan feedback ready: {len(findings)} findings, {count} annotations.")
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"AQB OpenScan feedback failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
