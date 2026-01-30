# Security Review Report

**Date**: {date}
**Review Type**: {review_type}
**Target**: {target}
**Framework Detected**: {framework}
**Reviewer**: Claude Security Review Skill

---

## 📊 Executive Summary

### MVP Phase Risk Assessment
- 🔴 **Critical**: {mvp_critical_count} findings
- 🟠 **High**: {mvp_high_count} findings
- 🟡 **Medium**: {mvp_medium_count} findings
- 🟢 **Low**: {mvp_low_count} findings
- ℹ️ **Info**: {mvp_info_count} findings

**MVP Launch Recommendation**: {mvp_recommendation}

### Production Phase Risk Assessment
- 🔴 **Critical**: {prod_critical_count} findings
- 🟠 **High**: {prod_high_count} findings
- 🟡 **Medium**: {prod_medium_count} findings
- 🟢 **Low**: {prod_low_count} findings
- ℹ️ **Info**: {prod_info_count} findings

**Production Readiness**: {prod_recommendation}

---

## 🔍 Detailed Findings

| # | Severity (MVP/Prod) | Category | File | Line | Finding | Recommendation |
|---|---------------------|----------|------|------|---------|----------------|
{findings_table}

---

## 🎯 Priority Actions

### Must Fix for MVP
{mvp_must_fix}

### Must Fix for Production
{prod_must_fix}

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

*This report was generated automatically by Claude Security Review Skill. Manual security testing and penetration testing are recommended for production deployments.*
