# Vuln-Sandbox Regression Test Manifest

This manifest lists every intentionally vulnerable file in the sandbox alongside its CWE, Sicario rule ID, and expected severity output. It doubles as a regression test manifest — if `sicario scan vuln-sandbox/` produces a different finding count or a mismatched rule ID, something has changed in the rule engine.

> **⚠️ WARNING: These files are intentionally vulnerable. Never deploy this code.**

---

## Summary

| Language          | File Count |
|-------------------|------------|
| Node.js           | 40         |
| Python            | 29         |
| React/TypeScript  | 10         |
| **Total**         | **79**     |

Expected total finding count: **79** (one finding per file).

---

## Node.js (`vuln-sandbox/node/`)

| File | CWE | Rule ID | Expected Severity |
|------|-----|---------|-------------------|
| `node/cwe-89/sql-injection.js` | CWE-89 | SqlStringConcat | CRITICAL |
| `node/cwe-89/sql-template-string.js` | CWE-89 | SqlTemplateString | CRITICAL |
| `node/cwe-78/command-injection.js` | CWE-78 | InjectChildProcessShellTrue | CRITICAL |
| `node/cwe-22/path-traversal.js` | CWE-22 | InputPathTraversal | HIGH |
| `node/cwe-79/innerhtml-xss.js` | CWE-79 | DomInnerHTML | HIGH |
| `node/cwe-95/eval-injection.js` | CWE-95 | InjectEval | CRITICAL |
| `node/cwe-918/ssrf-http-get.js` | CWE-918 | SsrfHttpGetUserInput | HIGH |
| `node/cwe-918/ssrf-fetch.js` | CWE-918 | SsrfFetchUserInput | HIGH |
| `node/cwe-693/helmet-missing.js` | CWE-693 | WebHelmetMissing | MEDIUM |
| `node/cwe-693/csp-missing.js` | CWE-693 | WebCspMissing | MEDIUM |
| `node/cwe-319/hsts-disabled.js` | CWE-319 | WebHstsDisabled | MEDIUM |
| `node/cwe-942/cors-credentials-wildcard.js` | CWE-942 | WebCorsCredentialsWildcard | HIGH |
| `node/cwe-200/referrer-policy-missing.js` | CWE-200 | WebReferrerPolicyMissing | LOW |
| `node/cwe-1021/clickjacking.js` | CWE-1021 | WebClickjacking | MEDIUM |
| `node/cwe-525/cache-control-missing.js` | CWE-525 | WebCacheControlMissing | LOW |
| `node/cwe-1321/prototype-pollution-merge.js` | CWE-1321 | PrototypePollutionMerge | HIGH |
| `node/cwe-1321/prototype-pollution-set.js` | CWE-1321 | PrototypePollutionSet | HIGH |
| `node/cwe-20/req-body-no-validation.js` | CWE-20 | InputReqBodyNoValidation | MEDIUM |
| `node/cwe-1333/regex-dos.js` | CWE-1333 | InputRegexDos | MEDIUM |
| `node/cwe-755/json-parse-no-try-catch.js` | CWE-755 | InputJsonParseNoTryCatch | LOW |
| `node/cwe-434/file-upload-no-mime-check.js` | CWE-434 | FileUploadNoMimeCheck | HIGH |
| `node/cwe-400/file-read-sync.js` | CWE-400 | FileReadSync | MEDIUM |
| `node/cwe-326/tls-min-version.js` | CWE-326 | TlsMinVersion | HIGH |
| `node/cwe-295/tls-cert-verify-disabled.js` | CWE-295 | TlsCertVerifyDisabledNode | CRITICAL |
| `node/cwe-798/aws-hardcoded-access-key.js` | CWE-798 | AwsHardcodedAccessKey | CRITICAL |
| `node/cwe-732/aws-s3-public-read-acl.js` | CWE-732 | AwsS3PublicReadAcl | HIGH |
| `node/cwe-1004/session-no-httponly.js` | CWE-1004 | AuthSessionNoHttpOnly | MEDIUM |
| `node/cwe-614/session-no-secure-flag.js` | CWE-614 | AuthSessionNoSecureFlag | MEDIUM |
| `node/cwe-384/session-fixation.js` | CWE-384 | AuthSessionFixation | HIGH |
| `node/cwe-532/password-in-log.js` | CWE-532 | AuthPasswordInLog | HIGH |
| `node/cwe-523/basic-auth-over-http.js` | CWE-523 | AuthBasicAuthOverHttp | HIGH |
| `node/cwe-613/jwt-no-expiry.js` | CWE-613 | AuthJwtNoExpiry | MEDIUM |
| `node/cwe-347/jwt-none-algorithm.js` | CWE-347 | CryptoJwtNoneAlgorithm | CRITICAL |
| `node/cwe-327/jwt-weak-algorithm.js` | CWE-327 | CryptoJwtWeakAlgorithm | HIGH |
| `node/cwe-916/pbkdf2-low-iterations.js` | CWE-916 | CryptoPbkdf2LowIterations | MEDIUM |
| `node/cwe-326/rsa-key-too-short.js` | CWE-326 | CryptoRsaKeyTooShort | HIGH |
| `node/cwe-321/hardcoded-aes-key.js` | CWE-321 | CryptoHardcodedAesKey | CRITICAL |
| `node/cwe-90/ldap-injection.js` | CWE-90 | InjectLdap | HIGH |
| `node/cwe-643/xpath-injection.js` | CWE-643 | InjectXpath | HIGH |
| `node/cwe-601/open-redirect.js` | CWE-601 | ReactWindowLocation | MEDIUM |

---

## Python (`vuln-sandbox/python/`)

| File | CWE | Rule ID | Expected Severity |
|------|-----|---------|-------------------|
| `python/cwe-215/django-debug-true.py` | CWE-215 | DjangoDebugTrue | MEDIUM |
| `python/cwe-215/flask-debug-true.py` | CWE-215 | FlaskDebugTrue | MEDIUM |
| `python/cwe-798/django-secret-key-hardcoded.py` | CWE-798 | DjangoSecretKeyHardcoded | CRITICAL |
| `python/cwe-798/flask-secret-key-hardcoded.py` | CWE-798 | FlaskSecretKeyHardcoded | CRITICAL |
| `python/cwe-798/flask-sqlalchemy-uri-hardcoded.py` | CWE-798 | FlaskSqlAlchemyUriHardcoded | CRITICAL |
| `python/cwe-798/aws-hardcoded-access-key.py` | CWE-798 | AwsHardcodedAccessKey | CRITICAL |
| `python/cwe-183/django-allowed-hosts-wildcard.py` | CWE-183 | DjangoAllowedHostsWildcard | MEDIUM |
| `python/cwe-352/django-csrf-exempt.py` | CWE-352 | DjangoCsrfExempt | HIGH |
| `python/cwe-89/sql-injection.py` | CWE-89 | SqlStringConcat | CRITICAL |
| `python/cwe-78/command-injection.py` | CWE-78 | InjectPythonSubprocessShell | CRITICAL |
| `python/cwe-94/ssti.py` | CWE-94 | InjectSsti | CRITICAL |
| `python/cwe-90/ldap-injection.py` | CWE-90 | InjectLdap | HIGH |
| `python/cwe-643/xpath-injection.py` | CWE-643 | InjectXpath | HIGH |
| `python/cwe-918/ssrf-http-get.py` | CWE-918 | SsrfHttpGetUserInput | HIGH |
| `python/cwe-502/unsafe-deserialize.py` | CWE-502 | PyUnsafeDeserialize | CRITICAL |
| `python/cwe-295/requests-verify-false.py` | CWE-295 | PyRequestsVerifyFalse | HIGH |
| `python/cwe-377/temp-file-insecure.py` | CWE-377 | FileTempFileInsecure | MEDIUM |
| `python/cwe-732/file-permissions-world-writable.py` | CWE-732 | FilePermissionsWorldWritable | HIGH |
| `python/cwe-732/aws-s3-public-read-acl.py` | CWE-732 | AwsS3PublicReadAcl | HIGH |
| `python/cwe-916/pbkdf2-low-iterations.py` | CWE-916 | CryptoPbkdf2LowIterations | MEDIUM |
| `python/cwe-916/md5-password-hash.py` | CWE-916 | CryptoMd5PasswordHash | HIGH |
| `python/cwe-326/rsa-key-too-short.py` | CWE-326 | CryptoRsaKeyTooShort | HIGH |
| `python/cwe-321/hardcoded-aes-key.py` | CWE-321 | CryptoHardcodedAesKey | CRITICAL |
| `python/cwe-335/insecure-random-seed.py` | CWE-335 | CryptoInsecureRandomSeed | MEDIUM |
| `python/cwe-347/jwt-none-algorithm.py` | CWE-347 | CryptoJwtNoneAlgorithm | CRITICAL |
| `python/cwe-327/jwt-weak-algorithm.py` | CWE-327 | CryptoJwtWeakAlgorithm | HIGH |
| `python/cwe-760/hardcoded-salt.py` | CWE-760 | CryptoHardcodedSalt | HIGH |
| `python/cwe-532/password-in-log.py` | CWE-532 | AuthPasswordInLog | HIGH |
| `python/cwe-613/jwt-no-expiry.py` | CWE-613 | AuthJwtNoExpiry | MEDIUM |

---

## React/TypeScript (`vuln-sandbox/react/`)

| File | CWE | Rule ID | Expected Severity |
|------|-----|---------|-------------------|
| `react/cwe-79/dangerously-set-inner-html.tsx` | CWE-79 | ReactDangerouslySetInnerHTML | HIGH |
| `react/cwe-95/eval-injection.tsx` | CWE-95 | InjectEval | CRITICAL |
| `react/cwe-79/href-javascript.tsx` | CWE-79 | ReactHrefJavascript | HIGH |
| `react/cwe-601/open-redirect.tsx` | CWE-601 | ReactWindowLocation | MEDIUM |
| `react/cwe-922/local-storage-token.tsx` | CWE-922 | ReactLocalStorageToken | MEDIUM |
| `react/cwe-362/use-effect-missing-dep.tsx` | CWE-362 | ReactUseEffectMissingDep | LOW |
| `react/cwe-79/dom-document-write.tsx` | CWE-79 | DomDocumentWrite | HIGH |
| `react/cwe-346/dom-post-message-wildcard.tsx` | CWE-346 | DomPostMessageWildcard | MEDIUM |
| `react/cwe-942/cors-wildcard.tsx` | CWE-942 | WebCorsWildcard | HIGH |
| `react/cwe-614/cookie-insecure.tsx` | CWE-614 | WebCookieInsecure | MEDIUM |

---

## How to Use as a Regression Test

Scan the entire sandbox and verify the finding count matches the total above:

```bash
# CI smoke test — run from repo root
sicario scan vuln-sandbox/ --format json | jq '.findings | length'
# Expected output: 79
```

Scan a specific language subdirectory:

```bash
sicario scan vuln-sandbox/node/     # expect 40 findings
sicario scan vuln-sandbox/python/   # expect 29 findings
sicario scan vuln-sandbox/react/    # expect 10 findings
```

Verify a specific rule fires with the correct severity:

```bash
sicario scan vuln-sandbox/node/cwe-89/sql-injection.js --format json \
  | jq '.findings[] | {rule_id, severity}'
# Expected: { "rule_id": "SqlStringConcat", "severity": "CRITICAL" }
```

If the finding count changes or a rule ID / severity does not match this manifest, a rule has been added, removed, or modified. Update this manifest accordingly and commit the change alongside the rule change.

---

## Severity Breakdown

| Severity | Count |
|----------|-------|
| CRITICAL | 19    |
| HIGH     | 33    |
| MEDIUM   | 23    |
| LOW      | 4     |
| **Total**| **79**|

> **Note:** All paths in the table above are relative to `vuln-sandbox/`. The `vuln-sandbox/` directory is excluded from production scans via the root `.sicarioignore` entry.
