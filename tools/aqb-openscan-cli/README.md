# aqb-openscan-cli binaries

Build metadata supplied with the binaries: Go 1.26.5, `CGO_ENABLED=0`,
`-trimpath`, and `-s -w`.
Version: `dev` (the original source directory had no Git metadata).
Build timestamp: `2026-10-14T09:32:39Z`.

The pipeline uses `aqb-openscan-cli-linux-amd64` from this directory on Ubuntu
24.04. It verifies the binary against `checksums-linux.txt` before execution.
Only that Linux amd64 binary, its checksum, and this README are included in Git.
The other platform builds and the combined `checksums.txt` are local files;
Windows commands below require the corresponding local build.

| Platform | Architecture | Binary |
| --- | --- | --- |
| Linux | x64 (amd64) | `aqb-openscan-cli-linux-amd64` |
| Linux | ARM64 | `aqb-openscan-cli-linux-arm64` |
| Windows | x64 (amd64) | `aqb-openscan-cli-windows-amd64.exe` |
| Windows | ARM64 | `aqb-openscan-cli-windows-arm64.exe` |

Run from the workspace root on Windows x64:

```powershell
.\tools\aqb-openscan-cli\aqb-openscan-cli-windows-amd64.exe version
.\tools\aqb-openscan-cli\aqb-openscan-cli-windows-amd64.exe scan . `
  --exclude 'tools/*,.github/*,.cryptoscan-baseline/*' `
  --format json --pretty --no-color --output polyglot-findings.json
```

Run from the workspace root on Linux x64:

```bash
chmod +x ./tools/aqb-openscan-cli/aqb-openscan-cli-linux-amd64
./tools/aqb-openscan-cli/aqb-openscan-cli-linux-amd64 version
./tools/aqb-openscan-cli/aqb-openscan-cli-linux-amd64 scan . \
  --exclude 'tools/*,.github/*,.cryptoscan-baseline/*' \
  --format json --pretty --no-color --output polyglot-findings.json
```

Use the ARM64 binary on ARM64 machines. SHA-256 hashes are in `checksums.txt`.

To update the CI binary, regenerate its checksum from this directory with
`sha256sum aqb-openscan-cli-linux-amd64 > checksums-linux.txt`.

The default scan exits with status 1 when critical findings are present, even
when it successfully writes the report. The pipeline validates the report and
accepts that finding status; execution errors still fail the job.

Configuration is read from `.aqb-openscan-cli.yaml`. Imports, quantum-safe
algorithms, and narrative mentions are suppressed by default. Use
`--include-imports`, `--include-quantum-safe`, or `--include-narrative` to include
those findings, or `--verbose` for all three. CI uses the defaults.

The CLI documents limitations: DSA key generation and compound identifiers
such as `RSAPrivateKey` are not detected. Git-history scanning, configurable
context depth, maximum depth, and non-file grouping flags are not implemented.
Results are pattern matches that require source review.

Original build validation: `go test ./...` and `go vet ./...` passed on Windows.
`go test -race ./...` passed in a Linux container using Go 1.27.1.
The x64 binaries ran sample scans on Windows and Linux (WSL), each reporting
110 findings. The scans returned exit code 1 because the samples contain
critical findings, as expected. ARM64 targets were cross-compiled and their
embedded platform metadata verified; they were not run on ARM64 hardware.

Pipeline migration validation: the Linux amd64 binary passed checksum
verification and the workflow's current-source, comparison-source, and SARIF
steps against a clean copy of this repository. It produced 20 findings across
all five sample components, with matching JSON/SARIF output and all five report
artifacts. Both comparison and inventory feedback passed. The 25 Python helper
tests passed on Linux and Windows, and the four PR publisher tests passed on
Windows with Node.js.
