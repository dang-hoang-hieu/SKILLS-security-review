---
name: security-review
description: Perform comprehensive security review of code changes, git diffs, pull requests, or entire codebase. Detects vulnerabilities, secrets, authentication issues, and OWASP compliance. Generates severity-rated reports with MVP and Production phase distinctions.
context: fork
agent: Explore
allowed-tools: [read_file, grep_search, semantic_search, run_in_terminal]
disable-model-invocation: false
argument-hint: [codebase|commit:<hash>|pr:<number>|path:<directory>]
---

# Security Review Skill

This skill performs automated security reviews on code with intelligent analysis and phase-specific severity ratings.

## Usage Modes

### Phase Selection (Required)

Specify review phase for accurate severity assessment:
- **mvp** - MVP/Pre-launch phase (focus on critical vulnerabilities only)
- **production** - Production-ready phase (comprehensive security hardening)

### Review Targets

1. **Full codebase review**: `/security-review mvp` or `/security-review production codebase`
2. **Commit review**: `/security-review mvp commit:abc123`
3. **Pull request review**: `/security-review production pr:123`
4. **Directory review**: `/security-review mvp path:src/auth`

**Default**: If phase not specified, defaults to `production` (stricter checks)

## Review Process

### Complete Workflow (One Command)

Use the unified review script that handles analysis, report generation, and file saving:

```bash
# Full codebase review
python scripts/review.py <mvp|production> [path]

# Commit review
python scripts/review.py <mvp|production> commit:abc123

# Pull request review
python scripts/review.py <mvp|production> pr:123

# Git range review
python scripts/review.py <mvp|production> range:main..feature
```

**Output:**
- Creates report file in `reports/security-review-<phase>-<timestamp>.md`
- Displays report content in response
- Shows file path for future reference

### Manual Step-by-Step (Advanced)

If you need to run steps separately:

**Step 1: Analyze Target**

Run the appropriate Python script with phase parameter:

- **Codebase**: `python scripts/analyze_codebase.py [path] --phase=<mvp|production>`
- **Changes**: `python scripts/analyze_changes.py <commit-hash-or-pr-number> --phase=<mvp|production>`

**Step 2: Security Checklist Review**

For each file/folder group, check against these security categories:

#### 🔐 Authentication & Authorization
- Weak password policies or storage
- Missing multi-factor authentication
- Insecure session management
- JWT token vulnerabilities
- Missing authorization checks on sensitive operations
- Role-based access control (RBAC) bypasses
- OAuth/OIDC misconfigurations

#### 🛡️ Input Validation & Injection
- SQL injection vulnerabilities
- NoSQL injection risks
- Command injection (exec, eval, system calls)
- LDAP injection
- XML External Entity (XXE) injection
- Server-Side Request Forgery (SSRF)
- Path traversal vulnerabilities
- Unsafe deserialization

#### 🔑 Secrets & Sensitive Data
- Hardcoded API keys, passwords, tokens
- Private keys in repository
- Database credentials in code
- AWS/GCP/Azure access keys
- Secrets in logs or error messages
- Missing encryption for sensitive data
- Insecure cryptographic algorithms

#### 🌐 API & Web Security
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Missing security headers (CSP, HSTS, X-Frame-Options)
- CORS misconfiguration
- Insecure direct object references (IDOR)
- Mass assignment vulnerabilities
- Rate limiting absence
- Unvalidated redirects

#### 📦 Dependencies & Configuration
- Outdated dependencies with known CVEs
- Insecure default configurations
- Debug mode enabled in production
- Excessive error information disclosure
- Missing security patches
- Vulnerable third-party libraries

#### 🔒 Data Protection
- Unencrypted data transmission (missing HTTPS)
- Weak encryption algorithms (MD5, SHA1)
- Insecure random number generation
- Missing data sanitization before output
- PII/PHI without proper protection
- Insufficient logging and monitoring

#### 🚀 Business Logic & Race Conditions
- Race condition vulnerabilities
- Time-of-check to time-of-use (TOCTOU)
- Business logic bypasses
- Insufficient anti-automation
- Missing idempotency checks

For detailed examples of each vulnerability type, reference the `examples.md` file sections:
- Search for "# Authentication Examples" for auth issues
- Search for "# Injection Examples" for SQL/command injection
- Search for "# Secrets Examples" for credential patterns
- Search for "# XSS Examples" for cross-site scripting
- And so on for each category

**Step 3: Severity Rating**

Evaluate findings based on **selected phase**:

**MVP Phase** (Time-to-market priority - ship fast, block exploits):
- **CRITICAL**: Hardcoded secrets, SQL injection, authentication bypass, RCE
- **HIGH**: Authorization issues, XSS, CSRF
- **INFO**: All other findings (defer to production phase)

**Production Phase** (Security-hardened - comprehensive protection):
- **CRITICAL**: Any vulnerability allowing data breach or system compromise
- **HIGH**: Missing MFA, weak session management, incomplete input validation, XSS, CSRF
- **MEDIUM**: Rate limiting, weak crypto, info disclosure, outdated dependencies, missing monitoring
- **LOW**: Security headers, minor misconfigurations
- **INFO**: Documentation, code quality, testing recommendations

**Note**: The `--phase` flag ensures only relevant severity levels are applied to findings.

**Step 4: Generate Report** (handled automatically by `review.py` script)

---

## Framework-Specific Patterns

The analysis scripts automatically detect and apply framework-specific checks:

- **Django**: Check for safe template rendering, ORM injection, middleware security
- **Flask**: Validate session configuration, template auto-escaping, CORS setup
- **Express.js**: Check helmet middleware, parameterized queries, JWT validation
- **Spring Boot**: Verify @PreAuthorize usage, SQL injection in JPA, CORS config
- **React/Vue**: Check for dangerouslySetInnerHTML, XSS in props
- **FastAPI**: Validate dependency injection security, Pydantic validation

## Output Format

Reports include:
- Executive summary with phase-specific risk counts
- Findings table with severity, file location, description
- Remediation recommendations
- Framework-specific security checklist compliance
- Timestamp and review metadata

## Best Practices

1. Run security reviews on every PR before merge
2. Address all CRITICAL and HIGH severity issues for MVP launches
3. Implement full Production phase recommendations before production deployment
4. Re-run reviews after dependency updates
5. Use this skill alongside manual penetration testing for comprehensive coverage
