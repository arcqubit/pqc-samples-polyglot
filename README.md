# Polyglot Application - Multi-Language Vulnerable Sample

**WARNING**: This is an intentionally vulnerable application for testing purposes. DO NOT use any of this code in production.

## Overview

A multi-language monorepo demonstrating cryptographic vulnerabilities across different programming languages and tech stacks. This sample showcases the PQC Scanner's ability to detect inconsistent security practices across a polyglot codebase.

## Technology Stack

- **Frontend**: JavaScript/TypeScript (React)
- **Backend**: Python (Flask/FastAPI)
- **Microservices**: Go
- **Crypto Library**: Rust
- **Legacy Service**: Java

## Structure

```
polyglot-app/
├── frontend/          # JavaScript - RSA-1024, MD5
├── backend/           # Python - ECDSA, SHA-1
├── microservices/     # Go - DES, weak random
├── lib-crypto/        # Rust - Mixed (some secure, some weak)
└── legacy-service/    # Java - Multiple crypto issues
```

## Intentional Vulnerabilities by Component

### Frontend (JavaScript/TypeScript)
- RSA-1024 for client-side encryption
- MD5 for cache keys and checksums
- Weak random number generation
- **Expected**: 8 vulnerabilities

### Backend (Python)
- ECDSA with P-256 (quantum-vulnerable)
- SHA-1 for API token generation
- Hardcoded secret keys
- RC4 for session encryption
- **Expected**: 10 vulnerabilities

### Microservices (Go)
- DES encryption for inter-service communication
- MD5 for service discovery hashing
- Weak random for request IDs
- No forward secrecy in TLS
- **Expected**: 7 vulnerabilities

### Crypto Library (Rust)
- Mixed implementation (demonstrating partial migration)
- Some secure post-quantum algorithms
- Some legacy weak algorithms for compatibility
- **Expected**: 5 vulnerabilities

### Legacy Service (Java)
- 3DES for data encryption
- DSA-1024 signatures
- SHA-1 for logging and audit
- Weak TLS configuration
- **Expected**: 8 vulnerabilities

## Total Expected Results

- **Total Vulnerabilities**: 35+
- **Compliance Score**: 31/100
- **Risk Score**: 76/100
- **Demonstrates**: Cross-language consistency issues

## Key Findings

This sample repository demonstrates several real-world challenges:

1. **Inconsistent Security Levels**: Different teams using different crypto standards
2. **Legacy Compatibility**: Old services dragging down overall security posture
3. **Language-Specific Patterns**: Each language has common crypto anti-patterns
4. **Mixed Migration State**: Partial PQC adoption creating security gaps

## Scanning with PQC Scanner

The [CryptoScan workflow](.github/workflows/cryptoscan.yml), adapted from
`reality-copy`, runs the bundled Linux amd64 scanner on Ubuntu 24.04. It scans
the repository, including `frontend`, `backend`, `microservices`, `lib-crypto`,
and `legacy-service`, without building or installing the sample applications.
The scanner tools, workflow helpers, and comparison checkout are excluded.
The Linux executable's SHA-256 checksum is verified before each run.

It runs on relevant pushes to `main` and pull requests targeting `main`.
For a manual scan, open **Actions → CryptoScan → Run workflow** in GitHub.

Each run provides:

- An Actions summary with severity counts, source links, and expandable findings.
- Up to ten source warning annotations for high-confidence findings at medium
  severity or above. When a baseline exists, only new findings are annotated.
- One updating summary comment on same-repository pull requests. Fork PRs still
  receive Actions summaries and downloadable reports. Repository token policies
  can restrict comment publishing.
- A **cryptoscan-polyglot-report** artifact with `polyglot-findings.json`,
  `polyglot-findings.sarif`, Markdown, and `polyglot-findings.html`, retained for
  seven days. Download and extract it, then open the HTML to browse all findings.
- An optional upload to **Security → Code Scanning** when GitHub enables that
  feature for the repository. The Actions reports work without Code Scanning.

Pull requests compare against their base commit; pushes compare against the
previous commit. Both are scanned using the current scanner. Manual runs and
runs without an available comparison show an **Inventory**. Comparison matches
use the rule, repository-relative source path, and whitespace-normalized matched
line; line-number shifts do not create new findings. Renames or source-text
changes can appear as new findings.

This pipeline is **report only**, because the samples deliberately contain
vulnerabilities. Critical findings do not fail the scan job when the scanner
writes a valid report. Scanner execution errors, invalid reports, zero scanned
files, and JSON/SARIF inconsistencies fail the job. GitHub's optional native
Code Scanning checks apply their own severity policy. Scanner execution uses a
read-only token; PR feedback and Code Scanning uploads run in separate jobs.

Run the same scan locally from the repository root:

```powershell
# Windows
.\tools\cryptoscan\cryptoscan-windows-amd64.exe scan . `
  --exclude 'tools/*,.github/*,.cryptoscan-baseline/*' `
  --format json --pretty --no-color --output polyglot-findings.json
```

```sh
# Linux
chmod +x tools/cryptoscan/cryptoscan-linux-amd64
./tools/cryptoscan/cryptoscan-linux-amd64 scan . \
  --exclude 'tools/*,.github/*,.cryptoscan-baseline/*' \
  --format json --pretty --no-color --output polyglot-findings.json
```

The bundled CryptoScan reads `.cryptoscan.yaml` configuration, not the sample's
`.pqc-scanner.toml`. The expected results above describe the sample's original
PQC Scanner and are not assertions about CryptoScan's finding counts. See
[scanner usage](tools/cryptoscan/README.md) for exit behavior and limitations.

## Remediation Strategy

For a polyglot application, remediation should follow a unified crypto policy:

1. **Establish Baseline**: Minimum security standards across all languages
2. **Prioritize by Risk**: Fix critical vulnerabilities in all components first
3. **Unified Migration**: Coordinate PQC adoption across all services
4. **Shared Libraries**: Create common crypto libraries when possible
5. **Continuous Monitoring**: Regular scanning of all components

## Expected Remediation Impact

After applying unified crypto policy:
- Frontend: 100/100 (AES-256-GCM, SHA-256, crypto.randomBytes)
- Backend: 100/100 (Kyber-768, Dilithium2, proper key management)
- Microservices: 100/100 (AES-256-GCM, TLS 1.3 with forward secrecy)
- Crypto Library: 100/100 (Full PQC implementation)
- Legacy Service: 98/100 (Some constraints due to framework limitations)

**Final Overall Score: 100/100**

## Building and Testing

Each component has its own build system:

```bash
# Frontend
cd frontend && npm install && npm test

# Backend
cd backend && pip install -r requirements.txt && pytest

# Microservices
cd microservices && go build && go test

# Crypto Library
cd lib-crypto && cargo build && cargo test

# Legacy Service
cd legacy-service && mvn clean install && mvn test
```

## Notes for Developers

This sample demonstrates why **consistent security policies** and **automated scanning** are critical in polyglot environments. Without tooling like the PQC Scanner, vulnerabilities can easily slip through in the gaps between languages and teams.

## License

MIT - For testing purposes only
