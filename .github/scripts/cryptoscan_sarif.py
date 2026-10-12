"""Prepare CryptoScan SARIF for GitHub and verify it matches the JSON scan."""

from collections import Counter
import copy
import json
from pathlib import Path
import re
import sys
from urllib.parse import quote, unquote

from cryptoscan_report import validate_report


def repository_path(value, root):
    if not isinstance(value, str) or not value:
        raise ValueError("Finding is missing its source path")
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    relative = path.resolve().relative_to(root)
    if not path.is_file():
        raise ValueError(f"Finding source file does not exist: {relative}")
    return relative.as_posix()


def prepare_sarif(sarif, report, root, exit_code):
    _, total, _ = validate_report(report, exit_code)
    root = Path(root).resolve()
    if not isinstance(sarif, dict) or sarif.get("version") != "2.1.0":
        raise ValueError("Expected SARIF version 2.1.0")
    data = copy.deepcopy(sarif)
    runs = data.get("runs")
    if not isinstance(runs, list) or len(runs) != 1:
        raise ValueError("Expected exactly one CryptoScan SARIF run")
    run = runs[0]
    driver = run["tool"]["driver"]
    if driver.get("name") != "CryptoScan":
        raise ValueError("Unexpected SARIF tool")
    results = run.get("results")
    rules = driver.get("rules")
    # CryptoScan serializes empty slices as null; SARIF requires arrays.
    if results is None and total == 0:
        results = []
    if rules is None and total == 0:
        rules = []
    if not isinstance(results, list) or len(results) != total or not isinstance(rules, list):
        raise ValueError("SARIF result count does not match the JSON report")
    definitions = {rule["id"]: rule for rule in rules}
    stable_rules = {}
    expected = Counter()
    observed = Counter()
    for finding in report["findings"]:
        expected[(finding["id"], repository_path(finding["file"], root),
                  finding["line"], finding.get("column", 1))] += 1
    for result in results:
        occurrence = result["ruleId"]
        match = re.fullmatch(r"(.+)-\d+-\d+", occurrence)
        if occurrence not in definitions:
            raise ValueError(f"Missing or invalid SARIF rule: {occurrence}")
        locations = result.get("locations")
        if not isinstance(locations, list) or len(locations) != 1:
            raise ValueError("Expected one source location per finding")
        location = locations[0]["physicalLocation"]
        artifact = location["artifactLocation"]
        relative = repository_path(unquote(artifact["uri"]), root)
        region = location["region"]
        observed[(occurrence, relative, region["startLine"], region.get("startColumn", 1))] += 1
        artifact["uri"] = quote(relative, safe="/")
        # Dependency rules already have stable IDs without line/column suffixes.
        stable = match.group(1) if match else occurrence
        definition = copy.deepcopy(definitions[occurrence])
        definition["id"] = stable
        if stable in stable_rules:
            existing = copy.deepcopy(stable_rules[stable])
            existing_config = existing.pop("defaultConfiguration", {})
            incoming = copy.deepcopy(definition)
            incoming_config = incoming.pop("defaultConfiguration", {})
            if existing != incoming:
                raise ValueError(f"Conflicting definitions for SARIF rule: {stable}")
            # Imports can have lower severity than operational use of the same
            # pattern. Preserve result levels and use the highest rule default.
            levels = {"none": 0, "note": 1, "warning": 2, "error": 3}
            if levels[existing_config.get("level", "warning")] > levels[incoming_config.get("level", "warning")]:
                definition["defaultConfiguration"] = existing_config
        stable_rules[stable] = definition
        result["ruleId"] = stable
        result.setdefault("properties", {})["cryptoscanOccurrenceId"] = occurrence
    if expected != observed:
        raise ValueError("SARIF findings or source locations differ from the JSON report")
    run["results"] = results
    driver["rules"] = [stable_rules[key] for key in sorted(stable_rules)]
    data["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json"
    return data


def main():
    try:
        sarif_path, report_path, root = sys.argv[1:4]
        exit_code = int(sys.argv[4])
        path = Path(sarif_path)
        data = prepare_sarif(json.loads(path.read_text(encoding="utf-8")),
                             json.loads(Path(report_path).read_text(encoding="utf-8")),
                             root, exit_code)
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        run = data["runs"][0]
        print(f"SARIF ready: {len(run['results'])} results, {len(run['tool']['driver']['rules'])} rules.")
    except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
        print(f"CryptoScan SARIF failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
