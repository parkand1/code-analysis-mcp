"""Semgrep-based static analysis tools for Java/.NET modernization."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

RULES_DIR = Path(__file__).parent.parent / "rules"


def scan_code(
    code: str,
    language: str,
    filename: Optional[str] = None,
    rule_category: Optional[str] = None,
) -> dict:
    """Run semgrep static analysis on source code to detect modernization patterns.

    Scans code for deprecated APIs, legacy patterns, and migration opportunities
    using custom modernization rules for Java and .NET.

    Args:
        code: The source code to analyze.
        language: Programming language — java, csharp, python.
        filename: Optional filename hint (helps semgrep detect language).
        rule_category: Optional rule category filter — java-modernization, dotnet-modernization. Omit to use all rules for the language.
    """
    lang = language.lower().strip()

    # Map language to file extension
    ext_map = {"java": ".java", "csharp": ".cs", "c#": ".cs", "python": ".py"}
    ext = ext_map.get(lang, ".txt")

    if filename:
        ext = Path(filename).suffix or ext

    # Select rules
    if rule_category:
        config_path = RULES_DIR / f"{rule_category}.yaml"
        if not config_path.exists():
            return {"error": f"Rule category '{rule_category}' not found. Available: {_list_rule_files()}"}
        config = str(config_path)
    else:
        # Auto-select based on language
        if lang == "java":
            config = str(RULES_DIR / "java-modernization.yaml")
        elif lang in {"csharp", "c#"}:
            config = str(RULES_DIR / "dotnet-modernization.yaml")
        else:
            config = str(RULES_DIR)

    # Write code to temp file
    with tempfile.TemporaryDirectory() as tmpdir:
        target_file = Path(tmpdir) / f"input{ext}"
        target_file.write_text(code)

        try:
            result = subprocess.run(
                [
                    "semgrep",
                    "--config", config,
                    "--json",
                    "--no-git-ignore",
                    "--metrics", "off",
                    str(target_file),
                ],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=tmpdir,
            )

            output = json.loads(result.stdout) if result.stdout else {}

            findings = []
            for match in output.get("results", []):
                findings.append({
                    "rule_id": match.get("check_id", ""),
                    "message": match.get("extra", {}).get("message", ""),
                    "severity": match.get("extra", {}).get("severity", "WARNING"),
                    "line_start": match.get("start", {}).get("line", 0),
                    "line_end": match.get("end", {}).get("line", 0),
                    "matched_code": match.get("extra", {}).get("lines", ""),
                    "fix": match.get("extra", {}).get("fix", None),
                    "metadata": match.get("extra", {}).get("metadata", {}),
                })

            return {
                "language": language,
                "findings_count": len(findings),
                "findings": findings,
                "errors": output.get("errors", []),
            }

        except subprocess.TimeoutExpired:
            return {"error": "Semgrep scan timed out (60s limit)"}
        except FileNotFoundError:
            return {"error": "semgrep is not installed. Install with: pip install semgrep"}
        except json.JSONDecodeError:
            return {"error": f"Failed to parse semgrep output: {result.stderr}"}


def list_rules() -> dict:
    """List available semgrep rule categories and their descriptions.

    Returns metadata about the custom modernization rules available for scanning.
    """
    rules = []

    for rule_file in sorted(RULES_DIR.glob("*.yaml")):
        try:
            import yaml
            with open(rule_file) as f:
                content = yaml.safe_load(f)

            rule_ids = []
            if isinstance(content, dict) and "rules" in content:
                for rule in content["rules"]:
                    rule_ids.append({
                        "id": rule.get("id", ""),
                        "message": rule.get("message", ""),
                        "severity": rule.get("severity", "WARNING"),
                        "languages": rule.get("languages", []),
                    })

            rules.append({
                "category": rule_file.stem,
                "file": rule_file.name,
                "rule_count": len(rule_ids),
                "rules": rule_ids,
            })
        except Exception as e:
            rules.append({
                "category": rule_file.stem,
                "file": rule_file.name,
                "error": str(e),
            })

    return {"categories": rules, "total_categories": len(rules)}


def _list_rule_files() -> list[str]:
    return [f.stem for f in RULES_DIR.glob("*.yaml")]
