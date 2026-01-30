# Security Review Skill

A comprehensive Claude skill for automated security review of codebases, commits, and pull requests.

## 🎯 Features

- **Full Codebase Review**: Intelligent analysis of entire project structure with framework detection
- **Commit/PR Review**: Analyze specific changes with git diff parsing
- **Framework Detection**: Automatically detects Django, Flask, Express, React, Spring, and more
- **Phase-Based Severity**: Dual severity ratings for MVP and Production phases
- **Smart Organization**: Groups findings by folder and security category
- **Detailed Examples**: Comprehensive vulnerability examples with code samples
- **Automated Reports**: Generates structured markdown reports in `reports/` directory

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

1. **Full codebase review**:
   ```
   /security-review
   /security-review codebase
   ```

2. **Commit review**:
   ```
   /security-review commit:abc123
   ```

3. **Pull request review**:
   ```
   /security-review pr:42
   ```

4. **Directory review**:
   ```
   /security-review path:src/auth
   ```

### Standalone Scripts

```bash
# Analyze codebase
python scripts/analyze_codebase.py /path/to/project > analysis.json

# Analyze git changes
python scripts/analyze_changes.py commit:abc123 > changes.json
python scripts/analyze_changes.py pr:42 > pr-changes.json
python scripts/analyze_changes.py range:main..feature > range.json

# Generate report
python scripts/generate_report.py analysis.json reports/my-report.md
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

### MVP Phase
- **CRITICAL**: Hardcoded secrets, SQL injection, auth bypass, RCE
- **HIGH**: Authorization issues, XSS, CSRF
- **MEDIUM**: Missing rate limiting, weak crypto
- **LOW**: Missing headers, outdated deps (no active exploits)
- **INFO**: Code quality, best practices

### Production Phase
- **CRITICAL**: Any vulnerability allowing data breach/compromise
- **HIGH**: Missing MFA, weak sessions, incomplete validation
- **MEDIUM**: Outdated deps, missing monitoring
- **LOW**: Minor misconfigurations
- **INFO**: Documentation, testing recommendations

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

Reports are saved to `reports/security-review-<timestamp>.md` and include:

- Executive summary with phase-specific risk counts
- Detailed findings table with severity, location, and recommendations
- Framework-specific security checklist compliance
- Priority actions for MVP and Production
- Overall compliance score

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

1. Run security reviews on every PR before merge
2. Address all CRITICAL and HIGH severity issues before MVP launch
3. Implement full Production phase recommendations before production deployment
4. Re-run reviews after dependency updates
5. Use alongside manual penetration testing for comprehensive coverage

## 🔄 Installation

To use this skill in Claude Code:

1. Copy this directory to `~/.claude/skills/security-review/` for global use, or
2. Copy to `.claude/skills/security-review/` in your project for project-specific use

The skill will be available via `/security-review` command.

---

*Developed for automated security review with phase-specific severity assessment.*
