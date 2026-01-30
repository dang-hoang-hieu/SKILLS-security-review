# Security Review Skill

A comprehensive Claude skill for automated security review of codebases, commits, and pull requests.

## 🎯 Features

- **Full Codebase Review**: Intelligent analysis of entire project structure with framework detection
- **Commit/PR Review**: Analyze specific changes with git diff parsing
- **Framework Detection**: Automatically detects Django, Flask, Express, React, Spring, and more
- **Phase-Specific Severity**: Separate MVP and Production modes for accurate risk assessment
- **Smart Organization**: Groups findings by folder and security category
- **Detailed Examples**: Comprehensive vulnerability examples with code samples
- **Automated Reports**: Generates phase-specific markdown reports in `reports/` directory

## 📁 Structure

```
security-review/
├── SKILL.md                           # Main skill definition with YAML frontmatter
├── templates/
│   └── security-report-template.md   # Report template
├── examples.md                        # Vulnerability examples organized by category
├── scripts/
│   ├── analyze_codebase.py           # Full codebase analyzer
│   ├── analyze_changes.py            # Git diff/PR/commit analyzer
│   └── generate_report.py            # Report generator
└── reports/                           # Generated reports output here
```

## 🚀 Usage

### In Claude Code

**Phase Selection (Required)**:
- `mvp` - MVP/Pre-launch (focus on critical vulnerabilities only)
- `production` - Production-ready (comprehensive security hardening)

1. **Full codebase review**:
   ```
   /security-review mvp
   /security-review production codebase
   ```

2. **Commit review**:
   ```
   /security-review mvp commit:abc123
   /security-review production commit:abc123
   ```

3. **Pull request review**:
   ```
   /security-review mvp pr:42
   /security-review production pr:42
   ```

4. **Directory review**:
   ```
   /security-review path:src/auth
   ```

### Standalone Scripts

**Recommended: Use unified workflow script**

```bash
# Complete workflow (analyze + generate report + save file)
python scripts/review.py mvp /path/to/project
python scripts/review.py production .
python scripts/review.py mvp commit:abc123
python scripts/review.py production pr:42
```

**Advanced: Manual step-by-step**

```bash
# Step 1: Analyze
python scripts/analyze_codebase.py /path/to/project --phase=mvp > analysis.json
python scripts/analyze_changes.py commit:abc123 --phase=production > changes.json

# Step 2: Generate report
python scripts/generate_report.py analysis.json
```

## 🔐 Security Checks

- **Authentication & Authorization**: Weak passwords, missing MFA, authorization bypasses
- **Injection**: SQL, NoSQL, Command, LDAP, Path traversal
- **Secrets**: Hardcoded API keys, passwords, tokens, credentials
- **XSS/CSRF**: Cross-site scripting, CSRF token validation
- **API Security**: CORS, security headers, IDOR, rate limiting
- **Cryptography**: Weak algorithms, insecure random generation
- **Dependencies**: Outdated packages with known CVEs
- **Business Logic**: Race conditions, TOCTOU vulnerabilities

## 📊 Severity Levels

**Phase-Specific Evaluation**: Findings are rated based on selected phase for accurate prioritization.

### MVP Phase (Ship Fast - Block Exploits)
- **CRITICAL**: Hardcoded secrets, SQL injection, auth bypass, RCE
- **HIGH**: Authorization issues, XSS, CSRF, IDOR
- **INFO**: All other findings (rate limiting, weak crypto, headers, outdated deps, code quality)

*MVP focuses on immediate exploit risks only. Hardening items deferred to production.*

### Production Phase (Comprehensive Security)
- **CRITICAL**: Any vulnerability allowing data breach/compromise
- **HIGH**: Missing MFA, weak sessions, incomplete validation, XSS, CSRF
- **MEDIUM**: Rate limiting, weak crypto, info disclosure, outdated deps, monitoring
- **LOW**: Security headers, minor misconfigurations
- **INFO**: Documentation, testing, code quality

## 🛠️ Framework Detection

Automatically detects and applies framework-specific security checks for:
- Django
- Flask
- FastAPI
- Express.js
- Spring Boot
- React
- Vue
- Ruby on Rails
- Laravel
- Next.js

## 📝 Report Output

Reports are saved to `reports/security-review-<phase>-<timestamp>.md` and include:

- Executive summary with phase-specific risk assessment
- Detailed findings table with severity (for selected phase only)
- Framework-specific security checklist compliance
- Priority actions tailored to the selected phase
- Overall compliance score
- Phase-specific guidance and next steps

## 🔧 Requirements

- Python 3.6+ (stdlib only, no external dependencies)
- Git (for change analysis)
- GitHub CLI (optional, for PR analysis with `gh pr diff`)

## 📚 Examples Reference

The `examples.md` file contains detailed code samples for each vulnerability type, organized with clear section headers:

- `# Authentication Examples`
- `# Injection Examples`
- `# Secrets Examples`
- `# XSS Examples`
- `# CSRF Examples`
- `# CORS Examples`
- `# Security Headers Examples`
- `# Insecure Deserialization Examples`
- `# SSRF Examples`
- `# Race Condition Examples`
- `# Mass Assignment Examples`
- `# Cryptography Examples`
- `# Rate Limiting Examples`

## 🎯 Best Practices

1. **MVP Phase**: Run `/security-review mvp` on every PR - focus on blocking critical vulnerabilities
2. **Production Phase**: Run `/security-review production` before deployment - comprehensive hardening
3. Address all CRITICAL and HIGH severity issues for selected phase before proceeding
4. Re-run reviews with same phase after fixes to verify remediation
5. Transition from MVP to Production phase when ready for production deployment
6. Use alongside manual penetration testing for comprehensive coverage

## 🔄 Installation

To use this skill in Claude Code:

1. Copy this directory to `~/.claude/skills/security-review/` for global use, or
2. Copy to `.claude/skills/security-review/` in your project for project-specific use

The skill will be available via `/security-review` command.

---

*Developed for automated security review with phase-specific severity assessment.*
