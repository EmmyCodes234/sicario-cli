# sicario-rules

> Community-maintained security detection rules for [Sicario](https://usesicario.xyz).

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square)](LICENSE)
[![Rules](https://img.shields.io/badge/Rules-community-green?style=flat-square)](rules/)

---

## What this is

A collection of YAML security rules for the Sicario CLI. Rules here are maintained by the community under the Apache 2.0 license — no Rust source code, no build step, just YAML files and test fixtures.

Every rule in this repo can be loaded directly into Sicario using `--rules-dir`:

```bash
git clone https://github.com/sicario-labs/sicario-rules.git
sicario scan . --rules-dir sicario-rules/rules/
```

---

## Using these rules

**Load all community rules alongside built-ins:**
```bash
sicario scan . --rules-dir /path/to/sicario-rules/rules/
```

**Load rules for a specific language only:**
```bash
sicario scan . --rules-dir /path/to/sicario-rules/rules/javascript/
```

**User rules take precedence** — if a community rule has the same `id` as a built-in rule, the community rule wins. This lets you override built-in severity levels or patterns for your project.

---

## Repository structure

```
sicario-rules/
├── README.md
├── LICENSE                    ← Apache 2.0
├── CONTRIBUTING.md
├── rules/
│   ├── javascript/
│   │   ├── react-security.yaml
│   │   ├── node-auth.yaml
│   │   └── ...
│   ├── python/
│   │   ├── django-security.yaml
│   │   ├── flask-security.yaml
│   │   └── ...
│   ├── rust/
│   │   └── ...
│   ├── go/
│   │   └── ...
│   └── java/
│       └── ...
└── tests/
    └── fixtures/              ← Vulnerable code snippets for TP/TN validation
        ├── javascript/
        ├── python/
        └── ...
```

---

## Rule format

Each rule is a YAML document. Multiple rules can live in one file.

```yaml
- id: "js/react-dangerouslysetinnerhtml-user-input"
  name: "dangerouslySetInnerHTML with User Input"
  description: "Passing user-controlled data to dangerouslySetInnerHTML enables XSS attacks."
  severity: High
  languages:
    - JavaScript
    - TypeScript
  pattern:
    query: |
      (jsx_attribute
        (jsx_attribute_name) @attr (#eq? @attr "dangerouslySetInnerHTML")
        (jsx_expression
          (object
            (pair
              key: (property_identifier) @key (#eq? @key "__html")
              value: (_) @val)))) @xss
    captures:
      - "xss"
  cwe_id: "CWE-79"
  owasp_category: A03_Injection
  help_uri: "https://owasp.org/Top10/A03_2021-Injection/"
  test_cases:
    - code: |
        <div dangerouslySetInnerHTML={{ __html: userInput }} />
      expected: TruePositive
    - code: |
        <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }} />
      expected: TrueNegative
```

### Required fields

| Field | Type | Description |
|---|---|---|
| `id` | string | Unique rule identifier. Use `<lang>/<category>` format. |
| `name` | string | Short human-readable name. |
| `description` | string | What the vulnerability is and why it matters. |
| `severity` | enum | `Critical`, `High`, `Medium`, `Low`, or `Info` |
| `languages` | list | One or more of: `JavaScript`, `TypeScript`, `Python`, `Rust`, `Go`, `Java` |
| `pattern.query` | string | Tree-sitter S-expression query |
| `pattern.captures` | list | Capture names that represent the finding location |

### Optional fields

| Field | Type | Description |
|---|---|---|
| `cwe_id` | string | CWE identifier, e.g. `"CWE-79"` |
| `owasp_category` | string | OWASP Top 10 category |
| `help_uri` | string | Link to remediation guidance |
| `test_cases` | list | TP/TN test cases for `sicario rules test` |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions welcome — new rules, improved patterns, additional test cases, and new language coverage.

**Quick start:**
1. Fork this repo
2. Add your rule YAML to `rules/<language>/`
3. Add test fixtures to `tests/fixtures/<language>/`
4. Validate: `sicario rules validate --rules-dir rules/`
5. Test: `sicario rules test --rules-dir rules/`
6. Open a pull request

---

## License

Apache License 2.0. See [LICENSE](LICENSE).

Rules contributed here are freely usable in any project, commercial or otherwise.
