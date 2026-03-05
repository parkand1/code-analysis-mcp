# Code Analysis MCP Server

MCP server providing static analysis, AST parsing, and dependency scanning for Java/.NET modernization. Built with [FastMCP](https://gofastmcp.com/) and deployed to EKS.

## Tools (6)

### Semgrep (Static Analysis)
- `scan_code` — Run semgrep with custom Java/.NET modernization rules
- `list_rules` — List available rule categories and descriptions

### Tree-sitter (AST Parsing)
- `parse_code_structure` — Extract classes, methods, imports, inheritance from Java/C# code
- `find_code_patterns` — Search for deprecated APIs, annotations, synchronized blocks, etc.

### Dependency Scanning
- `scan_maven_dependencies` — Analyze pom.xml for outdated deps, Java version issues, AWS SDK v1
- `scan_nuget_dependencies` — Analyze .csproj for outdated packages, legacy target frameworks

## Custom Semgrep Rules

### Java Modernization (`rules/java-modernization.yaml`)
- `javax.*` → `jakarta.*` namespace migration
- `sun.misc.*` removed API detection
- `java.util.Date` → `java.time` candidates
- AWS SDK v1 → v2 migration
- Legacy collections (Vector, Hashtable)
- EJB annotation detection

### .NET Modernization (`rules/dotnet-modernization.yaml`)
- `System.Web` namespace (Framework-only)
- `HttpContext.Current` usage
- `ConfigurationManager` → `IConfiguration`
- `WebClient` → `HttpClient`
- WCF `[ServiceContract]` detection
- Web Forms page detection

## Run Locally

```bash
pip install -r requirements.txt
uvicorn server:app --host 0.0.0.0 --port 8080
```

MCP endpoint: `http://localhost:8080/mcp`

## Deploy to EKS

```bash
docker build -t code-analysis-mcp .
docker tag code-analysis-mcp:latest <account>.dkr.ecr.<region>.amazonaws.com/code-analysis-mcp:latest
docker push <account>.dkr.ecr.<region>.amazonaws.com/code-analysis-mcp:latest
kubectl apply -f k8s-deployment.yaml
```

## Connect from Modernization Agent

The modernization-agent connects via streamable-http:

```python
from strands.tools.mcp import MCPClient
from mcp.client.streamable_http import streamablehttp_client

mcp_client = MCPClient(lambda: streamablehttp_client("http://code-analysis-mcp:8080/mcp"))
agent = Agent(tools=[*ALL_TOOLS, mcp_client])
```
