#!/usr/bin/env python3
"""
Analyzer for git changes (commits, PRs, diffs).
Extracts and organizes changes by folder for security review.
"""

import os
import json
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Set


class ChangeAnalyzer:
    """Analyzes git changes for security review."""

    # Patterns for detecting sensitive changes
    SENSITIVE_PATTERNS = {
        'secrets': [
            r'api[_-]?key',
            r'secret[_-]?key',
            r'password',
            r'token',
            r'credential',
            r'private[_-]?key',
            r'aws[_-]?access',
            r'AKIA[0-9A-Z]{16}',  # AWS Access Key
            r'sk_live_[0-9a-zA-Z]{24,}',  # Stripe Live Key
            r'ghp_[0-9a-zA-Z]{36}',  # GitHub Personal Access Token
        ],
        'auth': [
            r'authenticate',
            r'authorize',
            r'login',
            r'session',
            r'jwt',
            r'oauth',
            r'@login_required',
            r'@require_auth',
        ],
        'sql': [
            r'execute\s*\(',
            r'cursor\.',
            r'\.raw\(',
            r'SELECT.*FROM',
            r'INSERT INTO',
            r'UPDATE.*SET',
            r'DELETE FROM',
        ],
        'dangerous_functions': [
            r'eval\s*\(',
            r'exec\s*\(',
            r'os\.system',
            r'subprocess\.call',
            r'shell=True',
            r'innerHTML',
            r'dangerouslySetInnerHTML',
        ],
    }

    # File extensions to analyze
    CODE_EXTENSIONS = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php',
        '.cs', '.cpp', '.c', '.h', '.sql', '.yml', '.yaml', '.json', '.xml',
        '.vue', '.html', '.env'
    }

    def __init__(self, repo_path: str = '.'):
        self.repo_path = Path(repo_path).resolve()
        self.changes = []

    def run_git_command(self, args: List[str]) -> str:
        """Run a git command and return output."""
        try:
            result = subprocess.run(
                ['git'] + args,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"Error running git command: {e}", file=sys.stderr)
            return ""

    def get_commit_diff(self, commit_hash: str) -> str:
        """Get diff for a specific commit."""
        return self.run_git_command(['show', commit_hash, '--unified=3'])

    def get_pr_diff(self, pr_number: str, base_branch: str = 'main') -> str:
        """
        Get diff for a PR. Assumes PR branch is available locally.
        For GitHub PRs, use: gh pr diff <pr_number>
        """
        # Try using GitHub CLI first
        try:
            result = subprocess.run(
                ['gh', 'pr', 'diff', pr_number],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

        # Fallback: compare with base branch
        return self.run_git_command(['diff', f'{base_branch}...HEAD'])

    def get_range_diff(self, start_ref: str, end_ref: str) -> str:
        """Get diff between two git references."""
        return self.run_git_command(['diff', f'{start_ref}..{end_ref}'])

    def parse_diff(self, diff_text: str) -> List[Dict]:
        """
        Parse git diff output into structured format.
        Returns list of changed files with their changes.
        """
        changes = []
        current_file = None
        current_hunk = []

        lines = diff_text.split('\n')

        for line in lines:
            # New file
            if line.startswith('diff --git'):
                if current_file and current_hunk:
                    current_file['hunks'].append(current_hunk)
                    changes.append(current_file)

                # Extract file path
                match = re.search(r'b/(.*?)$', line)
                if match:
                    file_path = match.group(1)
                    current_file = {
                        'path': file_path,
                        'hunks': [],
                        'additions': 0,
                        'deletions': 0,
                    }
                    current_hunk = []

            # File status
            elif line.startswith('new file'):
                if current_file:
                    current_file['status'] = 'added'
            elif line.startswith('deleted file'):
                if current_file:
                    current_file['status'] = 'deleted'
            elif line.startswith('rename from'):
                if current_file:
                    current_file['status'] = 'renamed'

            # Hunk header
            elif line.startswith('@@'):
                if current_hunk:
                    current_file['hunks'].append(current_hunk)
                current_hunk = [line]

            # Content lines
            elif current_file and (line.startswith('+') or line.startswith('-') or line.startswith(' ')):
                current_hunk.append(line)
                if line.startswith('+') and not line.startswith('+++'):
                    current_file['additions'] += 1
                elif line.startswith('-') and not line.startswith('---'):
                    current_file['deletions'] += 1

        # Add last file
        if current_file and current_hunk:
            current_file['hunks'].append(current_hunk)
            changes.append(current_file)

        return changes

    def categorize_changes(self, changes: List[Dict]) -> Dict[str, List[Dict]]:
        """Organize changes by directory/category."""
        categorized = {}

        for change in changes:
            path = Path(change['path'])

            # Skip non-code files
            if path.suffix not in self.CODE_EXTENSIONS:
                continue

            # Categorize by directory
            if len(path.parts) > 1:
                category = path.parts[0]  # Top-level directory
            else:
                category = 'root'

            if category not in categorized:
                categorized[category] = []

            categorized[category].append(change)

        return categorized

    def detect_security_issues(self, change: Dict) -> List[Dict]:
        """
        Detect potential security issues in a change.
        Returns list of issues found.
        """
        issues = []

        for hunk in change.get('hunks', []):
            hunk_text = '\n'.join(hunk)

            # Only check added lines
            added_lines = [line[1:] for line in hunk if line.startswith('+') and not line.startswith('+++')]
            added_text = '\n'.join(added_lines)

            # Check each pattern category
            for category, patterns in self.SENSITIVE_PATTERNS.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, added_text, re.IGNORECASE)
                    for match in matches:
                        issues.append({
                            'category': category,
                            'pattern': pattern,
                            'match': match.group(0),
                            'file': change['path'],
                        })

        return issues

    def analyze_changes(self, diff_text: str) -> Dict:
        """
        Main analysis function.
        Parses diff and organizes changes with security analysis.
        """
        # Parse diff
        changes = self.parse_diff(diff_text)

        # Categorize by directory
        categorized = self.categorize_changes(changes)

        # Detect security issues
        all_issues = []
        for change in changes:
            issues = self.detect_security_issues(change)
            all_issues.extend(issues)

        # Statistics
        total_additions = sum(c.get('additions', 0) for c in changes)
        total_deletions = sum(c.get('deletions', 0) for c in changes)

        summary = {
            'total_files': len(changes),
            'total_additions': total_additions,
            'total_deletions': total_deletions,
            'categories': {cat: len(files) for cat, files in categorized.items()},
            'security_issues': all_issues,
            'categorized_changes': categorized,
            'all_changes': changes,
        }

        return summary


def main():
    """Main execution function."""
    import sys
    import argparse

    parser = argparse.ArgumentParser(description='Analyze git changes for security review')
    parser.add_argument('target', help='commit-hash, pr:NUMBER, or range:START..END')
    parser.add_argument('repo_path', nargs='?', default='.', help='Repository path')
    parser.add_argument('--phase', choices=['mvp', 'production'], default='production',
                        help='Review phase: mvp (critical only) or production (comprehensive)')
    args = parser.parse_args()

    target = args.target
    repo_path = args.repo_path
    phase = args.phase
    # Determine analysis type
    if target.startswith('pr:'):
        pr_number = target.split(':', 1)[1]
        print(f"🔍 Analyzing PR #{pr_number}...", file=sys.stderr)
        diff_text = analyzer.get_pr_diff(pr_number)
    elif target.startswith('range:'):
        range_spec = target.split(':', 1)[1]
        start, end = range_spec.split('..')
        print(f"🔍 Analyzing range {start}..{end}...", file=sys.stderr)
        diff_text = analyzer.get_range_diff(start, end)
    else:
        # Assume commit hash
        print(f"🔍 Analyzing commit {target}...", file=sys.stderr)
        diff_text = analyzer.get_commit_diff(target)

    if not diff_text:
        print("❌ No changes found or git command failed", file=sys.stderr)
        sys.exit(1)

    # Analyze
    print("📊 Parsing and analyzing changes...", file=sys.stderr)
    summary = analyzer.analyze_changes(diff_text)

    # Print summary
    print(f"\n📝 Changes summary:", file=sys.stderr)
    print(f"   Files changed: {summary['total_files']}", file=sys.stderr)
    print(f"   Lines added: {summary['total_additions']}", file=sys.stderr)
    print(f"   Lines deleted: {summary['total_deletions']}", file=sys.stderr)

    if summary['security_issues']:
        print(f"\n⚠️  {len(summary['security_issues'])} potential security issues detected", file=sys.stderr)

        # Group by category
        by_category = {}
        for issue in summary['security_issues']:
            cat = issue['category']
            by_category[cat] = by_category.get(cat, 0) + 1

        for cat, count in sorted(by_category.items()):
            print(f"   {cat}: {count}", file=sys.stderr)

    print("\n📂 Categories:", file=sys.stderr)
    for cat, count in sorted(summary['categories'].items()):
        print(f"   {cat}: {count} files", file=sys.stderr)

    # Output JSON to stdout
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
