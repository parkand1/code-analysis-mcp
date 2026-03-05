"""Code Analysis MCP Server for Java/.NET modernization.

Provides static analysis (semgrep), AST parsing (tree-sitter), and
dependency scanning (Maven/NuGet) via the Model Context Protocol.
"""

from fastmcp import FastMCP
from typing import Optional

from tools.semgrep_tools import scan_code as _scan_code, list_rules as _list_rules
from tools.treesitter_tools import parse_code_structure as _parse_structure, find_code_patterns as _find_patterns
from tools.dependency_tools import scan_maven_dependencies as _scan_maven, scan_nuget_dependencies as _scan_nuget


mcp = FastMCP("Code Analysis MCP Server")


# ---------------------------------------------------------------------------
# Semgrep tools
# ---------------------------------------------------------------------------

@mcp.tool
def scan_code(
    code: str,
    language: str,
    filename: Optional[str] = None,
    rule_category: Optional[str] = None,
) -> dict:
    """Run semgrep static analysis on source code to detect modernization patterns.

    Scans code for deprecated APIs, legacy patterns, and migration opportunities
    using custom rules for Java and .NET modernization.

    Args:
        code: The source code to analyze.
        language: Programming language — java, csharp, python.
        filename: Optional filename hint for language detection.
        rule_category: Optional rule filter — java-modernization, dotnet-modernization.
    """
    return _scan_code(code=code, language=language, filename=filename, rule_category=rule_category)


@mcp.tool
def list_rules() -> dict:
    """List available semgrep rule categories and their descriptions.

    Returns metadata about all custom modernization rules available for scanning.
    """
    return _list_rules()


# ---------------------------------------------------------------------------
# Tree-sitter tools
# ---------------------------------------------------------------------------

@mcp.tool
def parse_code_structure(
    code: str,
    language: str,
) -> dict:
    """Parse source code and extract its structure — classes, methods, imports, inheritance.

    Uses tree-sitter to build an AST and extract key structural elements
    of Java or C# source code.

    Args:
        code: The source code to parse.
        language: Programming language — java, csharp.
    """
    return _parse_structure(code=code, language=language)


@mcp.tool
def find_code_patterns(
    code: str,
    language: str,
    pattern_type: str,
) -> dict:
    """Search source code AST for specific patterns relevant to modernization.

    Looks for deprecated API usage, annotations, inheritance chains,
    static methods, synchronized blocks, and framework-specific imports.

    Args:
        code: The source code to search.
        language: Programming language — java, csharp.
        pattern_type: Pattern to find — deprecated_apis, annotations, inheritance, static_methods, synchronized_blocks, framework_imports.
    """
    return _find_patterns(code=code, language=language, pattern_type=pattern_type)


# ---------------------------------------------------------------------------
# Dependency tools
# ---------------------------------------------------------------------------

@mcp.tool
def scan_maven_dependencies(
    pom_xml: str,
) -> dict:
    """Parse a Maven pom.xml and identify outdated or problematic dependencies.

    Finds outdated libraries, deprecated packages, Java version issues,
    and AWS SDK v1 usage relevant to modernization.

    Args:
        pom_xml: The full content of a pom.xml file.
    """
    return _scan_maven(pom_xml=pom_xml)


@mcp.tool
def scan_nuget_dependencies(
    csproj_xml: str,
) -> dict:
    """Parse a .csproj file and identify outdated or problematic NuGet packages.

    Finds outdated packages, legacy target frameworks, and migration
    opportunities for .NET modernization.

    Args:
        csproj_xml: The full content of a .csproj file.
    """
    return _scan_nuget(csproj_xml=csproj_xml)


# ---------------------------------------------------------------------------
# ASGI app for deployment
# ---------------------------------------------------------------------------

import starlette.responses

_mcp_app = mcp.http_app(stateless_http=True)


async def health(request):
    return starlette.responses.JSONResponse({"status": "healthy", "tools": 6})


from starlette.routing import Route
from starlette.applications import Starlette

app = Starlette(
    routes=[
        Route("/health", health),
    ],
)
app.mount("/", _mcp_app)
