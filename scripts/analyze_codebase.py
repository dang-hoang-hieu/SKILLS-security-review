#!/usr/bin/env python3
"""
Intelligent codebase analyzer for security review.
Detects framework type and organizes code structure for review.
"""

import os
import json
import re
from pathlib import Path
from typing import Dict, List, Tuple, Set


class CodebaseAnalyzer:
    """Analyzes codebase structure and detects frameworks."""

    # Framework detection patterns
    FRAMEWORK_PATTERNS = {
        'django': ['manage.py', 'settings.py', 'wsgi.py', 'django'],
        'flask': ['app.py', 'flask', '__init__.py'],
        'fastapi': ['fastapi', 'main.py'],
        'express': ['express', 'package.json', 'app.js', 'server.js'],
        'spring': ['pom.xml', 'application.properties', 'spring'],
        'react': ['package.json', 'react', 'src/App.js', 'src/index.js'],
        'vue': ['package.json', 'vue', 'src/main.js'],
        'rails': ['Gemfile', 'config.ru', 'rails'],
        'laravel': ['artisan', 'composer.json', 'laravel'],
        'nextjs': ['next.config.js', 'pages/', 'package.json'],
    }

    # File extensions to analyze
    CODE_EXTENSIONS = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php',
        '.cs', '.cpp', '.c', '.h', '.sql', '.yml', '.yaml', '.json', '.xml'
    }

    # Directories to skip
    SKIP_DIRS = {
        'node_modules', 'venv', 'env', '.git', '__pycache__', 'dist', 'build',
        '.next', '.venv', 'vendor', 'target', '.idea', '.vscode', 'coverage',
        '.pytest_cache', 'eggs', 'wheels', '.tox'
    }

    # Security-sensitive file patterns
    SENSITIVE_PATTERNS = {
        'auth': ['auth', 'login', 'session', 'token', 'jwt', 'oauth', 'password'],
        'api': ['api', 'endpoint', 'route', 'controller', 'handler'],
        'database': ['model', 'schema', 'migration', 'query', 'db', 'database'],
        'config': ['config', 'settings', 'env', 'secret', 'credential'],
        'security': ['security', 'permission', 'access', 'role', 'middleware'],
    }

    def __init__(self, root_path: str = '.'):
        self.root_path = Path(root_path).resolve()
        self.detected_frameworks = []
        self.file_structure = {}

    def detect_frameworks(self) -> List[str]:
        """Detect frameworks used in the project."""
        detected = set()

        # Check root directory and immediate subdirectories
        for root, dirs, files in os.walk(self.root_path):
            # Skip deep nested directories for framework detection
            if root != str(self.root_path) and any(skip in root for skip in self.SKIP_DIRS):
                continue

            for framework, patterns in self.FRAMEWORK_PATTERNS.items():
                for pattern in patterns:
                    # Check files
                    if any(pattern in f for f in files):
                        detected.add(framework)
                    # Check directory names
                    if any(pattern in d for d in dirs):
                        detected.add(framework)
                    # Check file contents for imports
                    for file in files:
                        if file.endswith(('.py', '.js', '.ts')):
                            try:
                                file_path = Path(root) / file
                                content = file_path.read_text(encoding='utf-8', errors='ignore')
                                if pattern in content[:500]:  # Check first 500 chars
                                    detected.add(framework)
                            except:
                                pass

            # Only check first 2 levels
            depth = len(Path(root).relative_to(self.root_path).parts)
            if depth > 2:
                break

        self.detected_frameworks = sorted(detected)
        return self.detected_frameworks

    def categorize_file(self, file_path: Path) -> str:
        """Categorize a file based on its path and name."""
        path_str = str(file_path).lower()
        name = file_path.name.lower()

        for category, patterns in self.SENSITIVE_PATTERNS.items():
            if any(pattern in path_str or pattern in name for pattern in patterns):
                return category

        # Categorize by directory structure
        parts = file_path.parts
        if len(parts) > 1:
            # Use parent directory as category
            return parts[-2] if len(parts) > 2 else parts[-1]

        return 'other'

    def analyze_structure(self) -> Dict[str, List[Dict]]:
        """
        Analyze codebase and organize files into logical groups.
        Returns structure organized by category.
        """
        structure = {}
        total_files = 0

        for root, dirs, files in os.walk(self.root_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]

            root_path = Path(root)

            for file in files:
                file_path = root_path / file

                # Skip non-code files
                if file_path.suffix not in self.CODE_EXTENSIONS:
                    continue

                # Get relative path
                try:
                    rel_path = file_path.relative_to(self.root_path)
                except ValueError:
                    continue

                # Categorize file
                category = self.categorize_file(rel_path)

                if category not in structure:
                    structure[category] = []

                # Get file info
                file_info = {
                    'path': str(rel_path),
                    'name': file,
                    'extension': file_path.suffix,
                    'size': file_path.stat().st_size if file_path.exists() else 0,
                }

                structure[category].append(file_info)
                total_files += 1

                # Limit files per category to avoid overwhelming analysis
                if len(structure[category]) > 100:
                    continue

        self.file_structure = structure
        return structure

    def get_security_critical_files(self) -> List[str]:
        """Get list of security-critical files to prioritize."""
        critical_files = []

        priority_categories = ['auth', 'api', 'config', 'security']

        for category in priority_categories:
            if category in self.file_structure:
                for file_info in self.file_structure[category]:
                    critical_files.append(file_info['path'])

        return critical_files

    def generate_summary(self) -> Dict:
        """Generate analysis summary."""
        total_files = sum(len(files) for files in self.file_structure.values())

        summary = {
            'root_path': str(self.root_path),
            'frameworks': self.detected_frameworks,
            'total_files': total_files,
            'categories': {
                cat: len(files) for cat, files in self.file_structure.items()
            },
            'security_critical_files': self.get_security_critical_files(),
            'structure': self.file_structure
        }

        return summary


def main():
    """Main execution function."""
    import sys
    import argparse

    parser = argparse.ArgumentParser(description='Analyze codebase for security review')
    parser.add_argument('path', nargs='?', default='.', help='Path to analyze')
    parser.add_argument('--phase', choices=['mvp', 'production'], default='production',
                        help='Review phase: mvp (critical only) or production (comprehensive)')
    args = parser.parse_args()

    root_path = args.path
    phase = args.phase

    print(f"🔍 Analyzing codebase at: {root_path}", file=sys.stderr)
    print(f"📋 Phase: {phase.upper()}", file=sys.stderr)

    analyzer = CodebaseAnalyzer(root_path)

    # Detect frameworks
    print("🔧 Detecting frameworks...", file=sys.stderr)
    frameworks = analyzer.detect_frameworks()
    print(f"   Detected: {', '.join(frameworks) if frameworks else 'None'}", file=sys.stderr)

    # Analyze structure
    print("📁 Analyzing structure...", file=sys.stderr)
    structure = analyzer.analyze_structure()
    print(f"   Found {len(structure)} categories", file=sys.stderr)

    # Generate summary
    summary = analyzer.generate_summary()
    summary['phase'] = phase
    summary['review_type'] = 'Full Codebase Review'
    summary['target'] = root_path

    # Print category summary
    print("\n📊 Category breakdown:", file=sys.stderr)
    for cat, count in sorted(summary['categories'].items(), key=lambda x: -x[1]):
        print(f"   {cat}: {count} files", file=sys.stderr)

    print(f"\n🔐 {len(summary['security_critical_files'])} security-critical files identified", file=sys.stderr)

    # Output JSON to stdout for processing
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
