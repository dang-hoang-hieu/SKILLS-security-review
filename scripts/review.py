#!/usr/bin/env python3
"""
Complete security review workflow - analyze and generate report in one command.
"""

import sys
import json
import subprocess
import tempfile
from pathlib import Path


def run_review(phase, target_type, target_value, repo_path='.'):
    """Run complete security review workflow."""

    print(f"\n🔍 Security Review - {phase.upper()} Phase", file=sys.stderr)
    print(f"Target: {target_type} - {target_value}\n", file=sys.stderr)

    # Step 1: Run analysis
    print("📊 Step 1: Analyzing...", file=sys.stderr)

    if target_type == 'codebase':
        cmd = ['python3', 'scripts/analyze_codebase.py', target_value, f'--phase={phase}']
    else:
        cmd = ['python3', 'scripts/analyze_changes.py', target_value, repo_path, f'--phase={phase}']

    result = subprocess.run(cmd, capture_output=True, text=True)

    # Print stderr (progress messages)
    if result.stderr:
        print(result.stderr, file=sys.stderr)

    if result.returncode != 0:
        print(f"\n❌ Analysis failed: {result.stderr}", file=sys.stderr)
        sys.exit(1)

    # Parse analysis output
    try:
        analysis_data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"\n❌ Failed to parse analysis output: {e}", file=sys.stderr)
        print(f"Output was: {result.stdout[:500]}", file=sys.stderr)
        sys.exit(1)

    # Step 2: Generate report
    print("\n📝 Step 2: Generating report...", file=sys.stderr)

    # Save analysis to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(analysis_data, f, indent=2)
        temp_file = f.name

    # Generate report
    cmd = ['python3', 'scripts/generate_report.py', temp_file]
    result = subprocess.run(cmd, capture_output=True, text=True)

    # Print stderr (progress messages)
    if result.stderr:
        print(result.stderr, file=sys.stderr)

    if result.returncode != 0:
        print(f"\n❌ Report generation failed: {result.stderr}", file=sys.stderr)
        sys.exit(1)

    # Get report path from stdout
    report_path = result.stdout.strip()

    # Step 3: Read and display report
    print(f"\n✅ Report saved to: {report_path}\n", file=sys.stderr)

    report_content = Path(report_path).read_text(encoding='utf-8')

    # Output report to stdout
    print(report_content)

    # Cleanup
    Path(temp_file).unlink(missing_ok=True)


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description='Complete security review workflow')
    parser.add_argument('phase', choices=['mvp', 'production'],
                        help='Review phase: mvp or production')
    parser.add_argument('target', nargs='?', default='.',
                        help='Target: path, commit:hash, pr:number, range:start..end')
    parser.add_argument('--repo', default='.',
                        help='Repository path (for git analysis)')

    args = parser.parse_args()

    # Determine target type
    if args.target.startswith('commit:') or args.target.startswith('pr:') or args.target.startswith('range:'):
        target_type = 'changes'
        target_value = args.target
    else:
        target_type = 'codebase'
        target_value = args.target

    run_review(args.phase, target_type, target_value, args.repo)


if __name__ == '__main__':
    main()
