# Target Practice — Sicario Vulnerability Sandbox

> **⚠️ WARNING: These files are intentionally vulnerable. Never deploy this code.**

A deliberately vulnerable monorepo for testing Sicario. Safe to scan. Never deploy.

---

## Purpose

This sandbox gives you a safe, isolated target to verify Sicario's detection capabilities without touching your own codebase. Every file contains exactly one exploitable pattern that maps to a supported Sicario AST rule — no false positives, no extra noise.

Use it to:
- Confirm Sicario's sub-50ms scan speed on your machine
- Verify the zero-exfiltration guarantee (no code leaves your machine)
- Validate that rule IDs and severities match expected output
- Run regression checks after updating Sicario or custom rules

---

## Directory Structure

```
vuln-sandbox/
├── README.md          ← you are here
├── MANIFEST.md        ← regression test manifest (file → CWE → rule ID → expected severity)
├── node/
│   ├── cwe-89/        ← SQL Injection
│   │   └── sql-injection.js
│   ├── cwe-22/        ← Path Traversal
│   │   └── path-traversal.js
│   ├── cwe-78/        ← OS Command Injection
│   │   └── command-injection.js
│   └── ...            ← one subdirectory per CWE
├── python/
│   ├── cwe-89/
│   │   └── sql-injection.py
│   ├── cwe-22/
│   │   └── path-traversal.py
│   └── ...
└── react/
    ├── cwe-79/        ← Cross-Site Scripting (XSS)
    │   └── xss.tsx
    ├── cwe-95/        ← eval injection
    │   └── eval-injection.tsx
    └── ...
```

Each subdirectory is named `cwe-<ID>/` and contains a single file named after the Sicario rule ID (e.g. `sql-injection.js`). This 1:1 mapping makes it trivial to trace a finding back to its source pattern.

---

## How to Use

Scan the entire sandbox:

```bash
sicario scan vuln-sandbox/
```

Scan a specific language subdirectory:

```bash
sicario scan vuln-sandbox/node/
sicario scan vuln-sandbox/python/
sicario scan vuln-sandbox/react/
```

Scan a single CWE category:

```bash
sicario scan vuln-sandbox/node/cwe-89/
```

Expected output: **one finding per file**, matching the rule ID and severity listed in `MANIFEST.md`.

---

## Regression Test Manifest

`MANIFEST.md` lists every file in this sandbox alongside its CWE, Sicario rule ID, and expected severity. It doubles as a regression test manifest — if `sicario scan vuln-sandbox/` produces a different finding count or a mismatched rule ID, something has changed in the rule engine.

CI smoke test (run from repo root):

```bash
sicario scan vuln-sandbox/ --format json | jq '.findings | length'
# Should equal the total file count listed in MANIFEST.md
```

---

## Excluding from Production Scans

If you clone this repo and publish findings to the Sicario dashboard, add the following to your `.sicarioignore` to prevent sandbox findings from polluting your real results:

```
vuln-sandbox/
```

This entry is already present in the root `.sicarioignore` of this repository.

---

## Security Notice

These files exist solely as scan targets. They contain real vulnerability patterns and **must never be**:

- Deployed to any server or cloud environment
- Imported or required by production code
- Used as templates for application development

If you are contributing new vulnerable files, follow the one-pattern-per-file rule and update `MANIFEST.md` accordingly.
