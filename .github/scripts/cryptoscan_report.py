"""Display and validate a CryptoScan report for the report-only sample pipeline."""

import json
from pathlib import Path
import sys
import uuid


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def validate_report(report, exit_code):
    if not isinstance(report, dict):
        raise ValueError("Report must be a JSON object")
    findings = report.get("findings")
    summary = report.get("summary")
    if not isinstance(findings, list) or not isinstance(summary, dict):
        raise ValueError("Report must contain findings and summary fields")
    total = summary.get("totalFindings")
    if type(total) is not int or total != len(findings):
        raise ValueError("Finding count does not match the summary")
    files = report.get("filesScanned")
    if type(files) is not int or files <= 0:
        raise ValueError("Scanner did not scan any files")
    by_severity = summary.get("bySeverity")
    if not isinstance(by_severity, dict):
        raise ValueError("Report is missing severity counts")
    counts = {severity: by_severity.get(severity, 0) for severity in SEVERITIES}
    if any(type(count) is not int or count < 0 for count in counts.values()):
        raise ValueError("Severity counts must be nonnegative integers")
    if sum(counts.values()) != total:
        raise ValueError("Severity counts do not match the finding count")
    if exit_code != 0 and not (exit_code == 1 and counts["CRITICAL"] > 0):
        raise ValueError(f"Unexpected scanner exit code: {exit_code}")
    return files, total, counts


def display_json(raw):
    token = uuid.uuid4().hex
    print("::group::CryptoScan JSON results", flush=True)
    print(f"::stop-commands::{token}", flush=True)
    try:
        print(raw, flush=True)
    finally:
        print(f"::{token}::", flush=True)
        print("::endgroup::", flush=True)


def main():
    try:
        report_path = Path(sys.argv[1])
        exit_code = int(sys.argv[2])
        raw = report_path.read_text(encoding="utf-8")
        if "--quiet" not in sys.argv[3:]:
            display_json(raw)
        files, total, counts = validate_report(json.loads(raw), exit_code)
        print(f"Scan complete: {files} files, {total} findings (report only).")
    except (OSError, ValueError, KeyError, IndexError) as error:
        print(f"CryptoScan pipeline failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
