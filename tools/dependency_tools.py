"""Dependency scanning tools for Maven and NuGet projects."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Optional


# Known outdated versions for common dependencies
_JAVA_KNOWN_VERSIONS = {
    "spring-boot-starter": {"latest": "3.3.0", "eol": ["1.", "2."]},
    "spring-boot-starter-web": {"latest": "3.3.0", "eol": ["1.", "2."]},
    "spring-boot-starter-data-jpa": {"latest": "3.3.0", "eol": ["1.", "2."]},
    "spring-core": {"latest": "6.1.0", "eol": ["4.", "5.0", "5.1", "5.2"]},
    "spring-web": {"latest": "6.1.0", "eol": ["4.", "5.0", "5.1", "5.2"]},
    "junit": {"latest": "4.13.2", "note": "Migrate to JUnit 5 (org.junit.jupiter)"},
    "log4j-core": {"latest": "2.23.0", "eol": ["1."], "critical": "Log4j 1.x is EOL and has critical CVEs"},
    "javax.servlet-api": {"latest": "4.0.1", "note": "Migrate to jakarta.servlet-api for Jakarta EE"},
    "aws-java-sdk": {"latest": "1.12.700", "note": "Migrate to AWS SDK v2 (software.amazon.awssdk)"},
    "jackson-databind": {"latest": "2.17.0", "eol": ["2.9.", "2.10.", "2.11."]},
    "hibernate-core": {"latest": "6.4.0", "eol": ["4.", "5.0", "5.1", "5.2"]},
    "mysql-connector-java": {"latest": "8.3.0", "eol": ["5."]},
    "postgresql": {"latest": "42.7.0", "eol": ["9.", "42.1.", "42.2."]},
}

_DOTNET_KNOWN_VERSIONS = {
    "Microsoft.AspNetCore.Mvc": {"latest": "2.2.0", "note": "Included in framework. Use ASP.NET Core 10.0"},
    "Newtonsoft.Json": {"latest": "13.0.3", "note": "Consider System.Text.Json (built-in since .NET Core 3.0)"},
    "EntityFramework": {"latest": "6.4.4", "note": "Migrate to Microsoft.EntityFrameworkCore"},
    "Microsoft.EntityFrameworkCore": {"latest": "9.0.0", "eol": ["2.", "3.", "5."]},
    "System.Data.SqlClient": {"latest": "4.8.6", "note": "Use Microsoft.Data.SqlClient instead"},
    "Npgsql": {"latest": "8.0.0", "eol": ["4.", "5.", "6."]},
    "NLog": {"latest": "5.3.0", "eol": ["3.", "4."]},
    "log4net": {"latest": "2.0.17", "note": "Consider Microsoft.Extensions.Logging"},
    "AutoMapper": {"latest": "13.0.0", "eol": ["9.", "10.", "11."]},
    "Dapper": {"latest": "2.1.0", "eol": ["1."]},
}


def scan_maven_dependencies(
    pom_xml: str,
) -> dict:
    """Parse a Maven pom.xml and identify outdated or problematic dependencies.

    Analyzes the pom.xml content to find outdated libraries, deprecated packages,
    and Java version issues relevant to modernization.

    Args:
        pom_xml: The full content of a pom.xml file.
    """
    try:
        # Strip namespace for easier parsing
        cleaned = re.sub(r'\sxmlns="[^"]+"', '', pom_xml, count=1)
        root = ET.fromstring(cleaned)
    except ET.ParseError as e:
        return {"error": f"Failed to parse pom.xml: {e}"}

    result = {
        "java_version": None,
        "source_version": None,
        "target_version": None,
        "parent": None,
        "dependencies": [],
        "findings": [],
    }

    # Extract Java version from properties
    props = root.find(".//properties")
    if props is not None:
        for prop in props:
            tag = prop.tag.lower()
            if "java.version" in tag or "maven.compiler.source" in tag:
                result["java_version"] = prop.text
                result["source_version"] = prop.text
            if "maven.compiler.target" in tag:
                result["target_version"] = prop.text

    # Check Java version
    java_ver = result.get("java_version") or result.get("source_version")
    if java_ver:
        try:
            ver_num = int(java_ver.split(".")[0] if "." in java_ver else java_ver)
            if ver_num < 17:
                result["findings"].append({
                    "severity": "HIGH",
                    "type": "java_version",
                    "message": f"Java {java_ver} detected. Upgrade to Java 17+ via AWS Transform.",
                    "current": java_ver,
                    "recommended": "17",
                })
        except ValueError:
            pass

    # Extract parent
    parent = root.find("parent")
    if parent is not None:
        group_id = parent.findtext("groupId", "")
        artifact_id = parent.findtext("artifactId", "")
        version = parent.findtext("version", "")
        result["parent"] = {"groupId": group_id, "artifactId": artifact_id, "version": version}

        if "spring-boot" in artifact_id:
            try:
                major = int(version.split(".")[0])
                if major < 3:
                    result["findings"].append({
                        "severity": "HIGH",
                        "type": "spring_boot_version",
                        "message": f"Spring Boot {version} is EOL. Upgrade to 3.x (requires Java 17+).",
                        "current": version,
                        "recommended": "3.3.x",
                    })
            except (ValueError, IndexError):
                pass

    # Extract dependencies
    for dep in root.findall(".//dependencies/dependency"):
        group_id = dep.findtext("groupId", "")
        artifact_id = dep.findtext("artifactId", "")
        version = dep.findtext("version", "")
        scope = dep.findtext("scope", "compile")

        dep_info = {
            "groupId": group_id,
            "artifactId": artifact_id,
            "version": version or "(managed)",
            "scope": scope,
        }
        result["dependencies"].append(dep_info)

        # Check against known versions
        known = _JAVA_KNOWN_VERSIONS.get(artifact_id)
        if known and version:
            if known.get("critical"):
                for eol_prefix in known.get("eol", []):
                    if version.startswith(eol_prefix):
                        result["findings"].append({
                            "severity": "CRITICAL",
                            "type": "vulnerable_dependency",
                            "message": known["critical"],
                            "artifact": f"{group_id}:{artifact_id}",
                            "current": version,
                            "recommended": known["latest"],
                        })
                        break

            if known.get("note"):
                result["findings"].append({
                    "severity": "INFO",
                    "type": "migration_suggestion",
                    "message": known["note"],
                    "artifact": f"{group_id}:{artifact_id}",
                    "current": version,
                })

            if known.get("eol"):
                for eol_prefix in known["eol"]:
                    if version.startswith(eol_prefix):
                        result["findings"].append({
                            "severity": "MEDIUM",
                            "type": "outdated_dependency",
                            "message": f"{artifact_id} {version} is outdated/EOL.",
                            "artifact": f"{group_id}:{artifact_id}",
                            "current": version,
                            "recommended": known["latest"],
                        })
                        break

        # Detect javax namespace (should be jakarta for Java 17+)
        if group_id.startswith("javax."):
            result["findings"].append({
                "severity": "MEDIUM",
                "type": "javax_namespace",
                "message": f"javax namespace detected ({group_id}). Migrate to jakarta.* for Java 17+ / Jakarta EE.",
                "artifact": f"{group_id}:{artifact_id}",
            })

        # Detect AWS SDK v1
        if group_id == "com.amazonaws" and artifact_id.startswith("aws-java-sdk"):
            result["findings"].append({
                "severity": "LOW",
                "type": "aws_sdk_v1",
                "message": "AWS SDK for Java v1 detected. Upgrade to v2 (software.amazon.awssdk) via AWS Transform.",
                "artifact": f"{group_id}:{artifact_id}",
            })

    result["dependency_count"] = len(result["dependencies"])
    result["finding_count"] = len(result["findings"])

    return result


def scan_nuget_dependencies(
    csproj_xml: str,
) -> dict:
    """Parse a .csproj file and identify outdated or problematic NuGet packages.

    Analyzes the project file to find outdated packages, legacy target frameworks,
    and migration opportunities for .NET modernization.

    Args:
        csproj_xml: The full content of a .csproj file.
    """
    try:
        root = ET.fromstring(csproj_xml)
    except ET.ParseError as e:
        return {"error": f"Failed to parse .csproj: {e}"}

    result = {
        "target_framework": None,
        "is_sdk_style": False,
        "packages": [],
        "findings": [],
    }

    # Check SDK attribute (SDK-style = modern)
    if root.attrib.get("Sdk"):
        result["is_sdk_style"] = True

    # Extract target framework
    tf = root.findtext(".//TargetFramework") or root.findtext(".//TargetFrameworks")
    result["target_framework"] = tf

    if tf:
        tf_lower = tf.lower()
        if tf_lower.startswith("net4") or tf_lower.startswith("v4"):
            result["findings"].append({
                "severity": "HIGH",
                "type": "legacy_framework",
                "message": f".NET Framework {tf} detected. Modernize to .NET 10 via AWS Transform.",
                "current": tf,
                "recommended": "net10.0",
            })
        elif tf_lower.startswith("netcoreapp2") or tf_lower.startswith("netcoreapp3"):
            result["findings"].append({
                "severity": "MEDIUM",
                "type": "outdated_runtime",
                "message": f"{tf} is out of support. Upgrade to .NET 10.",
                "current": tf,
                "recommended": "net10.0",
            })
        elif tf_lower in {"net5.0", "net6.0", "net7.0"}:
            result["findings"].append({
                "severity": "MEDIUM",
                "type": "outdated_runtime",
                "message": f"{tf} is end-of-life. Upgrade to .NET 10 (LTS).",
                "current": tf,
                "recommended": "net10.0",
            })

    # Extract PackageReferences
    for pkg in root.findall(".//PackageReference"):
        name = pkg.attrib.get("Include", "")
        version = pkg.attrib.get("Version", "")

        pkg_info = {"name": name, "version": version or "(floating)"}
        result["packages"].append(pkg_info)

        # Check against known versions
        known = _DOTNET_KNOWN_VERSIONS.get(name)
        if known and version:
            if known.get("note"):
                result["findings"].append({
                    "severity": "INFO",
                    "type": "migration_suggestion",
                    "message": known["note"],
                    "package": name,
                    "current": version,
                })

            if known.get("eol"):
                for eol_prefix in known["eol"]:
                    if version.startswith(eol_prefix):
                        result["findings"].append({
                            "severity": "MEDIUM",
                            "type": "outdated_package",
                            "message": f"{name} {version} is outdated.",
                            "package": name,
                            "current": version,
                            "recommended": known["latest"],
                        })
                        break

    # Check for packages.config reference (old-style)
    if not result["is_sdk_style"]:
        result["findings"].append({
            "severity": "LOW",
            "type": "non_sdk_project",
            "message": "Non-SDK style project detected. Convert to SDK-style for modern .NET tooling.",
        })

    result["package_count"] = len(result["packages"])
    result["finding_count"] = len(result["findings"])

    return result
