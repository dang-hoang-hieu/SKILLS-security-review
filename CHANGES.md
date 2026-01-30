# Security Review Skill - Phase Severity Changes

## Summary

Simplified MVP phase severity levels to focus on immediate exploit risks only.

## Changes Made

### 1. MVP Severity Matrix (Simplified to 3 levels)

**Before:**
- CRITICAL, HIGH, MEDIUM, LOW, INFO (5 levels)

**After:**
- **CRITICAL**: Immediate exploit risks (secrets, SQL injection, auth bypass, RCE)
- **HIGH**: Serious vulnerabilities (XSS, CSRF, authorization, IDOR)
- **INFO**: Everything else (deferred to production)

### 2. Items Moved from MVP to Production Phase

These are now **INFO** for MVP (deferred), but properly rated in Production:
- Rate limiting: MVP INFO → Production MEDIUM
- Weak crypto: MVP INFO → Production MEDIUM  
- Info disclosure: MVP INFO → Production MEDIUM
- Security headers: MVP INFO → Production LOW
- Outdated dependencies (no exploits): MVP INFO → Production MEDIUM

### 3. Benefits

✅ **Clearer MVP reports**: Only shows blocking security issues
✅ **Faster shipping**: Not overwhelmed by hardening items
✅ **Better prioritization**: Focus on "can it be exploited now?"
✅ **Production comprehensive**: All items properly rated for production phase

### 4. Files Updated

- `SKILL.md` - Updated severity rating documentation
- `scripts/generate_report.py` - Updated SEVERITY_MATRIX
- `README.md` - Updated severity level documentation

## Usage Examples

### MVP Phase (Ship Fast)
```bash
python scripts/analyze_codebase.py . --phase=mvp
```
**Focus**: Block immediate exploits only
**Report shows**: CRITICAL and HIGH items only (INFO items listed but low priority)

### Production Phase (Comprehensive)
```bash
python scripts/analyze_codebase.py . --phase=production
```
**Focus**: Full security hardening
**Report shows**: All severity levels with proper rating

## Philosophy

- **MVP = "Can it be hacked today?"** → Block exploits, ship fast
- **Production = "Is it secure?"** → Comprehensive hardening, compliance

---

*Updated: 2026-01-30*
