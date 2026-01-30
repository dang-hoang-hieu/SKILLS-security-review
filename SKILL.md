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

1. **Full codebase review**: `/security-review codebase` or `/security-review`
2. **Commit review**: `/security-review commit:abc123`
3. **Pull request review**: `/security-review pr:123`
4. **Directory review**: `/security-review path:src/auth`

## Review Process

### Step 1: Analyze Target

Run the appropriate Python script based on the review type:

- **Codebase**: `python scripts/analyze_codebase.py`
- **Changes**: `python scripts/analyze_changes.py <commit-hash-or-pr-number>`

These scripts intelligently:
- Detect framework type (Django, Flask, Express, Spring, etc.)
- Traverse project structure and group files by logical folders
- Extract relevant code sections and changes
- Apply framework-specific security patterns

### Step 2: Security Checklist Review

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

### Step 3: Severity Rating

Evaluate each finding with **two-phase severity**:

**MVP Phase** (Time-to-market priority):
- **CRITICAL**: Hardcoded secrets, SQL injection, authentication bypass, RCE
- **HIGH**: Authorization issues, XSS, CSRF without auth impact
- **MEDIUM**: Missing rate limiting, weak crypto, info disclosure
- **LOW**: Missing security headers, outdated dependencies (no active exploits)
- **INFO**: Code quality, best practices, future improvements

**Production Phase** (Security-hardened):
- **CRITICAL**: Any vulnerability allowing data breach or system compromise
- **HIGH**: Missing MFA, weak session management, incomplete input validation
- **MEDIUM**: Outdated dependencies (even without exploits), missing monitoring
- **LOW**: Missing non-critical security headers, minor misconfigurations
- **INFO**: Documentation, security testing recommendations

### Step 4: Generate Report

Run: `python scripts/generate_report.py <analysis-output-json>`

This creates a structured report in `reports/security-review-<timestamp>.md` using the template from `templates/security-report-template.md`.

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
