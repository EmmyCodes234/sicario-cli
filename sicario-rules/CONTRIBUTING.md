# Contributing to sicario-rules

Thank you for contributing. This repo accepts YAML rule files and test fixtures only — no Rust source code required.

## Getting started

1. Install Sicario: `curl -fsSL https://usesicario.xyz/install.sh | sh`
2. Fork and clone this repo
3. Add your rule to `rules/<language>/your-rule-file.yaml`
4. Add test fixtures to `tests/fixtures/<language>/`
5. Validate and test your rule (see below)
6. Open a pull request

## Writing a rule

Rules are tree-sitter S-expression queries. The best way to develop one:

1. Find a vulnerable code pattern you want to detect
2. Use the [tree-sitter playground](https://tree-sitter.github.io/tree-sitter/playground) to explore the AST
3. Write an S-expression query that matches the vulnerable pattern
4. Add true-positive and true-negative test cases

See the [rule format documentation](README.md#rule-format) for the full field reference.

## Validating your rule

```bash
# Validate YAML syntax and required fields
sicario rules validate --rules-dir rules/

# Run TP/TN test cases
sicario rules test --rules-dir rules/

# Scan the test fixtures to verify detection
sicario scan tests/fixtures/ --rules-dir rules/ --format json
```

## Rule quality bar

- At least 3 true-positive test cases
- At least 2 true-negative test cases (to prevent false positives)
- CWE ID where applicable
- A `help_uri` pointing to remediation guidance
- No duplicate IDs with existing rules (check with `sicario rules validate`)

## Naming conventions

- Rule IDs: `<lang>/<category>-<pattern>` — e.g. `js/react-dangerouslysetinnerhtml`, `py/flask-debug-mode`
- File names: match the category — e.g. `rules/javascript/react-security.yaml`
- Keep related rules in the same file (e.g. all React XSS patterns in `react-security.yaml`)

## Pull request checklist

- [ ] Rule YAML is valid (`sicario rules validate` passes)
- [ ] Test cases pass (`sicario rules test` passes)
- [ ] Rule ID follows naming convention
- [ ] CWE ID included where applicable
- [ ] Description explains the vulnerability and its impact
- [ ] No duplicate IDs with existing rules

## License

By contributing, you agree that your contributions are licensed under the Apache License 2.0.
