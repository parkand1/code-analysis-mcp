"""Tree-sitter AST parsing tools for code structure extraction."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Optional

import tree_sitter


# Language registry — grammars loaded on first use
_languages: dict[str, tree_sitter.Language] = {}


def _get_language(lang: str) -> tree_sitter.Language:
    """Load and cache a tree-sitter language grammar."""
    if lang not in _languages:
        if lang == "java":
            import tree_sitter_java
            _languages["java"] = tree_sitter.Language(tree_sitter_java.language())
        elif lang in {"csharp", "c#"}:
            import tree_sitter_c_sharp
            _languages["csharp"] = tree_sitter.Language(tree_sitter_c_sharp.language())
            lang = "csharp"
        else:
            raise ValueError(f"Unsupported language: {lang}. Supported: java, csharp")
    return _languages.get(lang, _languages.get("csharp"))


def _get_parser(lang: str) -> tree_sitter.Parser:
    """Create a parser for the given language."""
    parser = tree_sitter.Parser()
    parser.language = _get_language(lang)
    return parser


def parse_code_structure(
    code: str,
    language: str,
) -> dict:
    """Parse source code and extract its structure — classes, methods, imports, inheritance.

    Uses tree-sitter to build an AST and extract the key structural elements
    of Java or C# source code.

    Args:
        code: The source code to parse.
        language: Programming language — java, csharp.
    """
    lang = language.lower().strip()
    if lang == "c#":
        lang = "csharp"

    try:
        parser = _get_parser(lang)
    except ValueError as e:
        return {"error": str(e)}

    tree = parser.parse(bytes(code, "utf-8"))
    root = tree.root_node

    result = {
        "language": language,
        "imports": [],
        "namespaces": [],
        "classes": [],
        "interfaces": [],
        "enums": [],
        "methods_outside_classes": [],
        "annotations": [],
        "errors": [],
    }

    if lang == "java":
        _extract_java_structure(root, result, code)
    elif lang == "csharp":
        _extract_csharp_structure(root, result, code)

    # Collect parse errors
    _collect_errors(root, result)

    return result


def find_code_patterns(
    code: str,
    language: str,
    pattern_type: str,
) -> dict:
    """Search source code AST for specific patterns relevant to modernization.

    Looks for patterns like deprecated API usage, specific annotations,
    inheritance from legacy base classes, etc.

    Args:
        code: The source code to search.
        language: Programming language — java, csharp.
        pattern_type: Pattern to search for — deprecated_apis, annotations, inheritance, static_methods, synchronized_blocks, framework_imports.
    """
    lang = language.lower().strip()
    if lang == "c#":
        lang = "csharp"

    try:
        parser = _get_parser(lang)
    except ValueError as e:
        return {"error": str(e)}

    tree = parser.parse(bytes(code, "utf-8"))
    root = tree.root_node

    matches = []

    if pattern_type == "deprecated_apis":
        matches = _find_deprecated_apis(root, lang, code)
    elif pattern_type == "annotations":
        matches = _find_annotations(root, lang, code)
    elif pattern_type == "inheritance":
        matches = _find_inheritance(root, lang, code)
    elif pattern_type == "static_methods":
        matches = _find_static_methods(root, lang, code)
    elif pattern_type == "synchronized_blocks":
        matches = _find_synchronized(root, lang, code)
    elif pattern_type == "framework_imports":
        matches = _find_framework_imports(root, lang, code)
    else:
        return {
            "error": f"Unknown pattern_type: {pattern_type}",
            "available_patterns": [
                "deprecated_apis", "annotations", "inheritance",
                "static_methods", "synchronized_blocks", "framework_imports",
            ],
        }

    return {
        "language": language,
        "pattern_type": pattern_type,
        "matches_count": len(matches),
        "matches": matches,
    }


# ---------------------------------------------------------------------------
# Java extraction
# ---------------------------------------------------------------------------

def _extract_java_structure(node, result, code):
    """Extract structure from Java AST."""
    for child in node.children:
        node_type = child.type

        if node_type == "import_declaration":
            import_text = _node_text(child, code).rstrip(";").replace("import ", "").strip()
            result["imports"].append(import_text)

        elif node_type == "package_declaration":
            pkg = _node_text(child, code).rstrip(";").replace("package ", "").strip()
            result["namespaces"].append(pkg)

        elif node_type == "class_declaration":
            result["classes"].append(_extract_java_class(child, code))

        elif node_type == "interface_declaration":
            result["interfaces"].append(_extract_java_interface(child, code))

        elif node_type == "enum_declaration":
            name_node = child.child_by_field_name("name")
            result["enums"].append({"name": _node_text(name_node, code) if name_node else "unknown"})

        elif node_type == "method_declaration":
            result["methods_outside_classes"].append(_extract_method_info(child, code))

        else:
            _extract_java_structure(child, result, code)


def _extract_java_class(node, code) -> dict:
    name_node = node.child_by_field_name("name")
    superclass_node = node.child_by_field_name("superclass")
    interfaces_node = node.child_by_field_name("interfaces")

    cls = {
        "name": _node_text(name_node, code) if name_node else "unknown",
        "extends": None,
        "implements": [],
        "methods": [],
        "fields": [],
        "line": node.start_point[0] + 1,
    }

    if superclass_node:
        cls["extends"] = _node_text(superclass_node, code).replace("extends ", "").strip()

    if interfaces_node:
        cls["implements"] = [
            _node_text(c, code) for c in interfaces_node.children
            if c.type not in {",", "implements"}
        ]

    body = node.child_by_field_name("body")
    if body:
        for child in body.children:
            if child.type == "method_declaration":
                cls["methods"].append(_extract_method_info(child, code))
            elif child.type == "field_declaration":
                cls["fields"].append({
                    "declaration": _node_text(child, code).strip().rstrip(";"),
                    "line": child.start_point[0] + 1,
                })

    return cls


def _extract_java_interface(node, code) -> dict:
    name_node = node.child_by_field_name("name")
    return {
        "name": _node_text(name_node, code) if name_node else "unknown",
        "line": node.start_point[0] + 1,
    }


# ---------------------------------------------------------------------------
# C# extraction
# ---------------------------------------------------------------------------

def _extract_csharp_structure(node, result, code):
    """Extract structure from C# AST."""
    for child in node.children:
        node_type = child.type

        if node_type == "using_directive":
            using_text = _node_text(child, code).rstrip(";").replace("using ", "").strip()
            result["imports"].append(using_text)

        elif node_type in {"namespace_declaration", "file_scoped_namespace_declaration"}:
            name_node = child.child_by_field_name("name")
            if name_node:
                result["namespaces"].append(_node_text(name_node, code))
            _extract_csharp_structure(child, result, code)

        elif node_type == "class_declaration":
            result["classes"].append(_extract_csharp_class(child, code))

        elif node_type == "interface_declaration":
            name_node = child.child_by_field_name("name")
            result["interfaces"].append({
                "name": _node_text(name_node, code) if name_node else "unknown",
                "line": child.start_point[0] + 1,
            })

        elif node_type == "enum_declaration":
            name_node = child.child_by_field_name("name")
            result["enums"].append({
                "name": _node_text(name_node, code) if name_node else "unknown",
            })

        elif node_type in {"declaration_list", "global_statement"}:
            _extract_csharp_structure(child, result, code)


def _extract_csharp_class(node, code) -> dict:
    name_node = node.child_by_field_name("name")
    bases_node = node.child_by_field_name("bases")

    cls = {
        "name": _node_text(name_node, code) if name_node else "unknown",
        "extends": None,
        "implements": [],
        "methods": [],
        "fields": [],
        "line": node.start_point[0] + 1,
    }

    if bases_node:
        base_types = [
            _node_text(c, code) for c in bases_node.children
            if c.type not in {":", ","}
        ]
        if base_types:
            cls["extends"] = base_types[0]
            cls["implements"] = base_types[1:]

    body = node.child_by_field_name("body")
    if body:
        for child in body.children:
            if child.type == "method_declaration":
                cls["methods"].append(_extract_method_info(child, code))
            elif child.type in {"field_declaration", "property_declaration"}:
                cls["fields"].append({
                    "declaration": _node_text(child, code).strip().rstrip(";"),
                    "line": child.start_point[0] + 1,
                })

    return cls


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _extract_method_info(node, code) -> dict:
    name_node = node.child_by_field_name("name")
    return_type_node = node.child_by_field_name("type")
    params_node = node.child_by_field_name("parameters")

    return {
        "name": _node_text(name_node, code) if name_node else "unknown",
        "return_type": _node_text(return_type_node, code) if return_type_node else "void",
        "parameters": _node_text(params_node, code) if params_node else "()",
        "line": node.start_point[0] + 1,
    }


def _node_text(node, code: str) -> str:
    if node is None:
        return ""
    return code[node.start_byte:node.end_byte]


def _collect_errors(node, result):
    if node.type == "ERROR":
        result["errors"].append({
            "line": node.start_point[0] + 1,
            "text": "Parse error",
        })
    for child in node.children:
        _collect_errors(child, result)


# ---------------------------------------------------------------------------
# Pattern finders
# ---------------------------------------------------------------------------

def _find_deprecated_apis(root, lang, code) -> list:
    """Find usage of known deprecated APIs."""
    deprecated = []
    if lang == "java":
        deprecated_patterns = [
            "sun.misc.", "java.util.Date", "java.util.Calendar",
            "java.util.Vector", "java.util.Hashtable", "java.util.Stack",
        ]
    elif lang == "csharp":
        deprecated_patterns = [
            "System.Web.", "HttpContext.Current", "ConfigurationManager",
            "WebClient", "System.Data.OleDb",
        ]
    else:
        return []

    _walk_for_text(root, code, deprecated_patterns, deprecated)
    return deprecated


def _find_annotations(root, lang, code) -> list:
    matches = []
    target_types = {"marker_annotation", "annotation"} if lang == "java" else {"attribute_list", "attribute"}
    _walk_for_types(root, code, target_types, matches)
    return matches


def _find_inheritance(root, lang, code) -> list:
    matches = []
    target_types = {"superclass", "super_interfaces"} if lang == "java" else {"base_list"}
    _walk_for_types(root, code, target_types, matches)
    return matches


def _find_static_methods(root, lang, code) -> list:
    matches = []
    for node in _walk_all(root):
        if node.type == "method_declaration":
            text = _node_text(node, code)
            if "static " in text[:100]:
                name_node = node.child_by_field_name("name")
                matches.append({
                    "text": _node_text(name_node, code) if name_node else "unknown",
                    "line": node.start_point[0] + 1,
                })
    return matches


def _find_synchronized(root, lang, code) -> list:
    matches = []
    if lang != "java":
        return matches
    target_types = {"synchronized_statement"}
    _walk_for_types(root, code, target_types, matches)
    return matches


def _find_framework_imports(root, lang, code) -> list:
    matches = []
    if lang == "java":
        target = {"import_declaration"}
    elif lang == "csharp":
        target = {"using_directive"}
    else:
        return matches
    _walk_for_types(root, code, target, matches)
    return matches


def _walk_for_text(node, code, patterns, results):
    text = _node_text(node, code)
    for pattern in patterns:
        if pattern in text and node.child_count == 0:
            results.append({
                "pattern": pattern,
                "text": text.strip()[:200],
                "line": node.start_point[0] + 1,
            })
    for child in node.children:
        _walk_for_text(child, code, patterns, results)


def _walk_for_types(node, code, target_types, results):
    if node.type in target_types:
        results.append({
            "type": node.type,
            "text": _node_text(node, code).strip()[:200],
            "line": node.start_point[0] + 1,
        })
    for child in node.children:
        _walk_for_types(child, code, target_types, results)


def _walk_all(node):
    yield node
    for child in node.children:
        yield from _walk_all(child)
