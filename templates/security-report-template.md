# Security Review Report - {phase} Phase

**Date**: {date}  
**Review Type**: {review_type}  
**Target**: {target}  
**Framework Detected**: {framework}  
**Phase**: {phase}  
**Reviewer**: Claude Security Review Skill

---

## 📊 Executive Summary

### {phase} Phase Risk Assessment
- 🔴 **Critical**: {critical_count} findings
- 🟠 **High**: {high_count} findings  
- 🟡 **Medium**: {medium_count} findings
- 🟢 **Low**: {low_count} findings
- ℹ️ **Info**: {info_count} findings

**{phase} Readiness**: {recommendation}

---

## 🔍 Detailed Findings

| # | Severity | Category | File | Line | Finding | Recommendation |
|---|----------|----------|------|------|---------|----------------|
{findings_table}

---

## 🎯 Priority Actions

### Must Fix for {phase}
{must_fix}

### Recommended Improvements
{recommended_improvements}

---

## 🛡️ Framework-Specific Security Checklist

### {framework} Security Best Practices

{framework_checklist}

---

## 📈 Compliance Status

| Security Category | Status | Notes |
|-------------------|--------|-------|
| Authentication & Authorization | {auth_status} | {auth_notes} |
| Input Validation & Injection Prevention | {input_status} | {input_notes} |
| Secrets Management | {secrets_status} | {secrets_notes} |
| API & Web Security | {api_status} | {api_notes} |
| Dependencies & Configuration | {deps_status} | {deps_notes} |
| Data Protection | {data_status} | {data_notes} |

**Overall Compliance Score**: {compliance_score}/100

---

## 📝 Notes

{additional_notes}

---

## 🔄 Next Steps

1. {next_step_1}
2. {next_step_2}
3. {next_step_3}

---

**Phase-Specific Guidance:**

- **MVP Phase**: Focus exclusively on CRITICAL and HIGH severity issues. These represent immediate security risks that could lead to data breaches or system compromise. MEDIUM and LOW severity items can be addressed in future iterations.

- **PRODUCTION Phase**: All severity levels should be addressed before deployment. This includes hardening security headers, updating dependencies, implementing comprehensive monitoring, and ensuring full OWASP compliance.

---

*This report was generated automatically by Claude Security Review Skill. Manual security testing and penetration testing are recommended for production deployments.*
