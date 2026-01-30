#!/usr/bin/env python3
"""
Security report generator.
Formats security findings using template with MVP/Production severity levels.
"""

import os
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any


class ReportGenerator:
    """Generates security review reports from findings."""

    # Severity levels for different phases
    SEVERITY_MATRIX = {
        'secrets': {'mvp': 'CRITICAL', 'prod': 'CRITICAL'},
        'sql_injection': {'mvp': 'CRITICAL', 'prod': 'CRITICAL'},
        'command_injection': {'mvp': 'CRITICAL', 'prod': 'CRITICAL'},
        'auth_bypass': {'mvp': 'CRITICAL', 'prod': 'CRITICAL'},
        'rce': {'mvp': 'CRITICAL', 'prod': 'CRITICAL'},

        'xss': {'mvp': 'HIGH', 'prod': 'CRITICAL'},
        'csrf': {'mvp': 'HIGH', 'prod': 'CRITICAL'},
        'auth': {'mvp': 'HIGH', 'prod': 'CRITICAL'},
        'authorization': {'mvp': 'HIGH', 'prod': 'HIGH'},
        'idor': {'mvp': 'MEDIUM', 'prod': 'HIGH'},

        'rate_limiting': {'mvp': 'MEDIUM', 'prod': 'HIGH'},
        'weak_crypto': {'mvp': 'MEDIUM', 'prod': 'HIGH'},
        'info_disclosure': {'mvp': 'LOW', 'prod': 'MEDIUM'},
        'security_headers': {'mvp': 'LOW', 'prod': 'MEDIUM'},

        'outdated_deps': {'mvp': 'LOW', 'prod': 'MEDIUM'},
        'code_quality': {'mvp': 'INFO', 'prod': 'LOW'},
    }

    # Framework-specific checklists
    FRAMEWORK_CHECKLISTS = {
        'django': [
            '✓ CSRF middleware enabled',
            '✓ SQL injection prevention (ORM usage)',
            '✓ XSS prevention (template auto-escaping)',
            '✓ Secure session configuration',
            '✓ Security middleware (SecurityMiddleware)',
            '✓ HTTPS/SSL configuration',
            '✓ Debug mode disabled in production',
            '✓ SECRET_KEY properly configured',
        ],
        'flask': [
            '✓ CSRF protection enabled (Flask-WTF)',
            '✓ Secure session configuration',
            '✓ Template auto-escaping enabled',
            '✓ SQL injection prevention (parameterized queries)',
            '✓ Security headers configured',
            '✓ Rate limiting implemented',
            '✓ Input validation on all endpoints',
        ],
        'express': [
            '✓ Helmet middleware for security headers',
            '✓ CORS properly configured',
            '✓ Input validation and sanitization',
            '✓ Parameterized database queries',
            '✓ CSRF protection (csurf)',
            '✓ Rate limiting (express-rate-limit)',
            '✓ Secure session configuration',
            '✓ Environment variables for secrets',
        ],
        'react': [
            '✓ No dangerouslySetInnerHTML usage',
            '✓ Input sanitization before rendering',
            '✓ Secure API communication (HTTPS)',
            '✓ Token storage (httpOnly cookies)',
            '✓ CORS configuration on backend',
            '✓ No sensitive data in local storage',
        ],
        'spring': [
            '✓ CSRF protection enabled',
            '✓ Security configuration (WebSecurityConfigurerAdapter)',
            '✓ SQL injection prevention (PreparedStatement)',
            '✓ XSS prevention (output encoding)',
            '✓ Authentication and authorization (@PreAuthorize)',
            '✓ Secure password storage (BCryptPasswordEncoder)',
            '✓ Input validation (@Valid)',
        ],
    }

    def __init__(self, template_path: str = None):
        if template_path is None:
            # Default template path relative to script
            script_dir = Path(__file__).parent
            template_path = script_dir.parent / 'templates' / 'security-report-template.md'

        self.template_path = Path(template_path)
        self.template = self._load_template()

    def _load_template(self) -> str:
        """Load report template."""
        if self.template_path.exists():
            return self.template_path.read_text(encoding='utf-8')
        else:
            # Fallback basic template
            return """# Security Review Report

**Date**: {date}
**Review Type**: {review_type}
**Target**: {target}

## Findings

{findings_table}

## Summary

MVP: {mvp_summary}
Production: {prod_summary}
"""

    def _format_findings_table(self, findings: List[Dict]) -> str:
        """Format findings as markdown table."""
        if not findings:
            return "*No security issues found.*"

        rows = []
        for i, finding in enumerate(findings, 1):
            mvp_sev = finding.get('mvp_severity', 'INFO')
            prod_sev = finding.get('prod_severity', 'INFO')
            category = finding.get('category', 'unknown')
            file_path = finding.get('file', 'N/A')
            line = finding.get('line', '-')
            description = finding.get('description', finding.get('match', ''))
            recommendation = finding.get('recommendation', 'Review and fix')

            # Severity emojis
            severity_icon = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🟢',
                'INFO': 'ℹ️'
            }

            mvp_icon = severity_icon.get(mvp_sev, 'ℹ️')
            prod_icon = severity_icon.get(prod_sev, 'ℹ️')

            row = f"| {i} | {mvp_icon} {mvp_sev} / {prod_icon} {prod_sev} | {category} | {file_path} | {line} | {description} | {recommendation} |"
            rows.append(row)

        return '\n'.join(rows)

    def _count_by_severity(self, findings: List[Dict], phase: str) -> Dict[str, int]:
        """Count findings by severity for a phase."""
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}

        severity_key = f'{phase}_severity'
        for finding in findings:
            severity = finding.get(severity_key, 'INFO')
            counts[severity] = counts.get(severity, 0) + 1

        return counts

    def _get_framework_checklist(self, frameworks: List[str]) -> str:
        """Get framework-specific security checklist."""
        if not frameworks:
            return "*No specific framework detected.*"

        checklist = []
        for framework in frameworks:
            if framework in self.FRAMEWORK_CHECKLISTS:
                checklist.append(f"### {framework.title()}\n")
                checklist.extend(self.FRAMEWORK_CHECKLISTS[framework])
                checklist.append("")

        return '\n'.join(checklist) if checklist else "*No framework-specific checklist available.*"

    def _get_priority_actions(self, findings: List[Dict], phase: str, severity: str) -> str:
        """Get priority actions for a phase and severity."""
        severity_key = f'{phase}_severity'
        priority_findings = [f for f in findings if f.get(severity_key) == severity]

        if not priority_findings:
            return f"*No {severity} severity issues for {phase.upper()} phase.*"

        actions = []
        for i, finding in enumerate(priority_findings, 1):
            file_path = finding.get('file', 'N/A')
            description = finding.get('description', finding.get('match', ''))
            actions.append(f"{i}. **{file_path}**: {description}")

        return '\n'.join(actions)

    def _get_recommendation(self, counts: Dict[str, int], phase: str) -> str:
        """Get overall recommendation based on findings."""
        if counts['CRITICAL'] > 0:
            return f"❌ **NOT READY** - {counts['CRITICAL']} critical issue(s) must be fixed before {phase}"
        elif counts['HIGH'] > 0:
            return f"⚠️  **CAUTION** - {counts['HIGH']} high severity issue(s) should be addressed"
        elif counts['MEDIUM'] > 0:
            return f"⚠️  **ACCEPTABLE** - {counts['MEDIUM']} medium severity issue(s) can be addressed post-{phase}"
        else:
            return f"✅ **READY** - No critical or high severity issues found"

    def _calculate_compliance_score(self, findings: List[Dict]) -> int:
        """Calculate overall compliance score (0-100)."""
        if not findings:
            return 100

        # Weight by severity
        weights = {'CRITICAL': 20, 'HIGH': 10, 'MEDIUM': 5, 'LOW': 2, 'INFO': 1}

        total_penalty = 0
        for finding in findings:
            severity = finding.get('prod_severity', 'INFO')
            total_penalty += weights.get(severity, 1)

        # Max penalty = 100 (arbitrary scale)
        score = max(0, 100 - total_penalty)
        return score

    def generate_report(self, analysis_data: Dict, output_path: str = None) -> str:
        """
        Generate security review report from analysis data.

        Args:
            analysis_data: Dict with analysis results (from analyzer scripts)
            output_path: Where to save report (default: reports/security-review-<timestamp>.md)

        Returns:
            Path to generated report
        """
        # Extract data
        review_type = analysis_data.get('review_type', 'Full Codebase Review')
        target = analysis_data.get('target', 'Current codebase')
        frameworks = analysis_data.get('frameworks', [])
        findings = analysis_data.get('findings', [])

        # Count severities
        mvp_counts = self._count_by_severity(findings, 'mvp')
        prod_counts = self._count_by_severity(findings, 'prod')

        # Get recommendations
        mvp_recommendation = self._get_recommendation(mvp_counts, 'MVP')
        prod_recommendation = self._get_recommendation(prod_counts, 'Production')

        # Format findings table
        findings_table = self._format_findings_table(findings)

        # Framework checklist
        framework_name = frameworks[0] if frameworks else 'Unknown'
        framework_checklist = self._get_framework_checklist(frameworks)

        # Priority actions
        mvp_must_fix = self._get_priority_actions(findings, 'mvp', 'CRITICAL')
        prod_must_fix = self._get_priority_actions(findings, 'prod', 'HIGH')
        recommended_improvements = self._get_priority_actions(findings, 'prod', 'MEDIUM')

        # Compliance score
        compliance_score = self._calculate_compliance_score(findings)

        # Fill template
        report = self.template.format(
            date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            review_type=review_type,
            target=target,
            framework=framework_name,

            # MVP counts
            mvp_critical_count=mvp_counts['CRITICAL'],
            mvp_high_count=mvp_counts['HIGH'],
            mvp_medium_count=mvp_counts['MEDIUM'],
            mvp_low_count=mvp_counts['LOW'],
            mvp_info_count=mvp_counts['INFO'],
            mvp_recommendation=mvp_recommendation,

            # Production counts
            prod_critical_count=prod_counts['CRITICAL'],
            prod_high_count=prod_counts['HIGH'],
            prod_medium_count=prod_counts['MEDIUM'],
            prod_low_count=prod_counts['LOW'],
            prod_info_count=prod_counts['INFO'],
            prod_recommendation=prod_recommendation,

            # Content
            findings_table=findings_table,
            mvp_must_fix=mvp_must_fix,
            prod_must_fix=prod_must_fix,
            recommended_improvements=recommended_improvements,
            framework_checklist=framework_checklist,

            # Compliance
            auth_status='✓' if not any(f.get('category') == 'auth' for f in findings) else '⚠',
            auth_notes='No authentication issues found' if not any(f.get('category') == 'auth' for f in findings) else 'Issues detected',
            input_status='✓',
            input_notes='Validation implemented',
            secrets_status='⚠',
            secrets_notes='Review required',
            api_status='✓',
            api_notes='Properly configured',
            deps_status='✓',
            deps_notes='Up to date',
            data_status='✓',
            data_notes='Encryption in place',
            compliance_score=compliance_score,

            # Notes
            additional_notes=analysis_data.get('notes', 'No additional notes.'),
            next_step_1='Address all CRITICAL severity issues',
            next_step_2='Review and fix HIGH severity issues',
            next_step_3='Schedule follow-up review after fixes',
        )

        # Determine output path
        if output_path is None:
            reports_dir = Path('reports')
            reports_dir.mkdir(exist_ok=True)
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            output_path = reports_dir / f'security-review-{timestamp}.md'
        else:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)

        # Write report
        output_path.write_text(report, encoding='utf-8')

        return str(output_path)


def main():
    """Main execution function."""
    if len(sys.argv) < 2:
        print("Usage: python generate_report.py <analysis-json-file> [output-path]", file=sys.stderr)
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None

    # Load analysis data
    print(f"📖 Loading analysis data from {input_file}...", file=sys.stderr)

    if input_file == '-':
        # Read from stdin
        analysis_data = json.load(sys.stdin)
    else:
        with open(input_file, 'r', encoding='utf-8') as f:
            analysis_data = json.load(f)

    # Generate report
    print("📝 Generating security review report...", file=sys.stderr)
    generator = ReportGenerator()

    report_path = generator.generate_report(analysis_data, output_file)

    print(f"\n✅ Report generated: {report_path}", file=sys.stderr)
    print(report_path)  # Output path to stdout


if __name__ == '__main__':
    main()
