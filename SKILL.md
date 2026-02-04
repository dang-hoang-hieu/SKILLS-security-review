---
name: security-review
description: Perform comprehensive security review of code changes, git diffs, pull requests, or entire codebase. Detects vulnerabilities, secrets, authentication issues, and OWASP compliance. Generates severity-rated reports with MVP and Production phase distinctions.
context: fork
agent: general-purpose
allowed-tools: [read_file, write_file, grep_search, semantic_search, run_in_terminal]
disable-model-invocation: false
argument-hint: [mvp|production] [codebase|commit:<hash>|pr:<number>|path:<directory>]
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

### ⚠️ IMPORTANT: Claude-Powered Analysis

This skill uses **Claude (you!)** to analyze security issues, NOT regex patterns. The workflow is:

1. **Extract Changes**: Run analyzer script to get git diff
2. **Claude Analyzes**: You read the formatted diff and identify real security issues
3. **Generate Report**: Create security report using template

### Workflow Steps

**Step 1: Extract Git Changes**

Run the analyzer to extract and format changes:

```bash
# For commit review
python3 .claude/skills/security-review/scripts/analyze_changes.py commit:<hash> <repo-path> --phase=<mvp|production>

# For PR review
python3 .claude/skills/security-review/scripts/analyze_changes.py pr:<number> <repo-path> --phase=<mvp|production>

# For range review
python3 .claude/skills/security-review/scripts/analyze_changes.py range:<start>..<end> <repo-path> --phase=<mvp|production>
```

**Output**: JSON with `formatted_diff` containing human-readable changes

**Step 2: Claude Security Analysis**

YOU (Claude) will analyze the `formatted_diff` to identify REAL security issues by checking:

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

**MVP vs Production Distinction:**
- **CSP Headers**: Weak CSP (e.g., `unsafe-inline`, `unsafe-eval`) is MEDIUM for MVP (defense-in-depth, needs XSS point), HIGH for Production
- **Input Validation**: Missing validation on non-auth fields (email format, etc.) is MEDIUM for MVP, HIGH for Production
- **Rate Limiting**: Memory-based or missing rate limits is MEDIUM for MVP (with strong passwords), HIGH for Production

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

**MVP Phase** (Time-to-market priority - ship fast, block direct exploits):
- **CRITICAL**: 
  - Hardcoded secrets (API keys, passwords directly in code)
  - SQL injection (direct database access)
  - Authentication bypass (no brute force required)
  - RCE (Remote Code Execution)
- **HIGH**: 
  - Authorization bypass (access resources without proper auth)
  - **Stored XSS** with confirmed injection point
  - CSRF on critical actions (payment, deletion, privilege changes)
- **MEDIUM**:
  - Missing rate limits (when strong password policy exists)
  - Weak/missing CSP headers (defense-in-depth measure)
  - Timing attacks (requires sophisticated analysis)
  - Reflected XSS (requires user interaction)
  - DoS/Memory leak vulnerabilities
- **INFO**: 
  - Security headers (HSTS, X-Frame-Options, etc.)
  - Outdated dependencies (no active exploit)
  - Code quality issues
  - Missing monitoring/logging

**Production Phase** (Security-hardened - comprehensive protection):
- **CRITICAL**: Any vulnerability allowing data breach or system compromise
- **HIGH**: Missing MFA, weak session management, incomplete input validation, stored XSS, CSRF, authorization issues
- **MEDIUM**: Rate limiting, weak crypto, CSP weaknesses, info disclosure, timing attacks, outdated dependencies, missing monitoring
- **LOW**: Security headers, minor misconfigurations, code quality
- **INFO**: Documentation, testing recommendations, best practices

**Note**: The `--phase` flag ensures only relevant severity levels are applied to findings.

**Severity Rating Philosophy (Based on OWASP Research):**
- **MVP**: Focus on single-condition exploits (direct access, no sophisticated techniques required)
- **Production**: Include defense-in-depth measures and multi-condition vulnerabilities
- **Rate Limiting**: Less critical with strong password policies (15+ chars); MFA more effective than rate limits (99.9% protection per Microsoft data)
- **CSP Headers**: Defense-in-depth only; requires existing XSS injection point to be exploitable
- **Timing Attacks**: Sophisticated technique requiring statistical analysis; low real-world exploitation rate for MVP stage

**Common Misclassifications to Avoid:**
- ❌ CSP with `unsafe-inline` → NOT High/Critical for MVP (needs XSS injection point first) → MEDIUM
- ❌ Missing email domain validation → NOT High for MVP (input validation, not auth bypass) → MEDIUM
- ❌ Rate limit bypass via header spoofing → NOT High for MVP (needs weak password) → MEDIUM
- ❌ Memory-based rate limiting → NOT Critical for MVP (production concern) → INFO for MVP, MEDIUM for Production
- ✅ Hardcoded API keys → CRITICAL for MVP (direct exploit)
- ✅ SQL injection → CRITICAL for MVP (direct DB access)
- ✅ Missing authentication on sensitive endpoint → CRITICAL for MVP (direct bypass)

**Step 3: Generate Security Report**

After analyzing the changes, create a markdown report following `templates/security-report-template.md`:

- List each finding with: severity (based on phase), category, file, line, description, recommendation
- Apply phase-specific severity using SEVERITY_MATRIX guidelines
- Include executive summary with risk counts
- Add framework-specific checklist compliance
- Provide priority actions and next steps

**CRITICAL**: Only report REAL security issues, not false positives like:
- Variable names containing "password", "token", "secret" (unless actual hardcoded secrets)
- Function names like "authenticate", "authorize" (unless missing proper implementation)
- UI component imports that match SQL patterns (like "Select" from shadcn/ui)

**⚠️ MANDATORY: Generate HTML Report and Minimal Terminal Output**

You MUST generate an HTML report and output ONLY minimal text to terminal.

**Template Selection**:
- MVP phase: Use `.claude/skills/security-review/templates/mvp-report.html`
- Production phase: Use `.claude/skills/security-review/templates/production-report.html`

**Steps**:
1. Analyze security issues from changes
2. Generate HTML report by replacing template variables:
   - `{{target}}` - commit hash or target description
   - `{{date}}` - current date
   - `{{critical_count}}`, `{{high_count}}`, `{{medium_count}}`, `{{low_count}}`, `{{info_count}}`
   - `{{status_class}}` - "pass", "warning", or "fail"
   - `{{status_text}}` - "✅ READY FOR {PHASE}", "⚠️ ISSUES FOUND", or "❌ CRITICAL ISSUES"
   - `{{findings_html}}` - HTML for each finding (see template structure)
   - `{{checklist_html}}` - Security checklist items (production only)
   - `{{timestamp}}` - current timestamp
3. Save HTML to: `.claude/skills/security-review/reports/security-review-<phase>-<YYYYMMDD-HHMMSS>.html`
4. **Output to terminal EXACTLY 2 lines (no more, no less)**:
   ```
   ✅ Report: file://<absolute-path-to-html>
   Status: [PASS/WARNING/FAIL] - [one short sentence]
   ```

**Example Terminal Output (MVP)**:
```
✅ Report: file:///home/user/project/.claude/skills/security-review/reports/security-review-mvp-20260204-143500.html
Status: ✅ READY FOR MVP - 0 critical/high issues found
```

**Example Terminal Output (Production)**:
```
✅ Report: file:///home/user/project/.claude/skills/security-review/reports/security-review-production-20260204-143500.html
Status: ⚠️ ISSUES FOUND - 2 medium issues require attention
```

**❌ CRITICAL - DO NOT**:
- Output ANY additional text beyond the 2 lines above
- Include summaries, lists, recommendations, or analysis in terminal
- Use markdown formatting in terminal output
- Add headers like "## Security Review Summary"
- List findings or positive improvements in terminal
- ALL details MUST be in the HTML report ONLY

---

## Framework-Specific Patterns

The analysis scripts automatically detect and apply framework-specific checks:

- **Django**: Check for safe template rendering, ORM injection, middleware security
- **Flask**: Validate session configuration, template auto-escaping, CORS setup
- **Express.js**: Check helmet middleware, parameterized queries, JWT validation
- **Spring Boot**: Verify @PreAuthorize usage, SQL injection in JPA, CORS config
- **React/Vue**: Check for dangerouslySetInnerHTML, XSS in props
- **FastAPI**: Validate dependency injection security, Pydantic validation

## Example Severity Ratings

To ensure consistency, here are examples of correct severity ratings:

### MVP Phase Examples

| Finding | MVP Severity | Rationale |
|---------|-------------|-----------|
| Hardcoded API key in code | CRITICAL | Direct exposure, no additional conditions needed |
| SQL injection in user input | CRITICAL | Direct database access possible |
| Admin endpoint without authentication | CRITICAL | Direct access without credentials |
| CSP allows `unsafe-inline` and `unsafe-eval` | MEDIUM | Requires XSS injection point to exploit |
| Missing email format validation | MEDIUM | Input validation issue, not authentication bypass |
| Rate limiting uses memory (no Redis) | INFO | MVP acceptable, production concern |
| Missing HSTS header | INFO | Security hardening, not immediate exploit |
| Memory-based session store | INFO | MVP acceptable with small user base |

### Production Phase Examples  

| Finding | Production Severity | Rationale |
|---------|-------------------|-----------|
| CSP allows `unsafe-inline` | HIGH | Defense-in-depth measure |
| Missing email domain validation | HIGH | Input validation completeness |
| Rate limiting uses memory | MEDIUM | Scalability and DoS concern |
| Missing rate limit on login | MEDIUM | Brute force prevention |
| Missing security headers | LOW | Hardening measures |

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
