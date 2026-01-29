# API Server Rationale

## Question: Is an API Server Necessary for Skill Scanner?

Unlike MCP Scanner, which scans **remote MCP servers** (HTTP/SSE/stdio connections), Skill Scanner scans **local skill packages** (files/directories). While an API server is less critical for Skill Scanner, it can provide additional support for CI/CD integration, web interfaces, service integrations, and batch processing. Read below for more details.

## Analysis

### Differences from MCP Scanner

**MCP Scanner:**
- Scans **remote** MCP servers via HTTP/SSE/stdio
- API server enables scanning servers you don't control
- Essential for the use case (scanning external services)

**Skill Scanner:**
- Scans **local** skill packages (files/directories)
- Skills are **always local** - there are no remote skills (unlike MCP servers)
- Skills are distributed as ZIP files or directories that users install locally
- Can be scanned directly via CLI or Python SDK
- **Key Point**: Remote skills do not exist - skills are local file packages

### Use Cases Where API is Valuable

Despite skills being local files, an API server provides value for:

#### 1. **CI/CD Integration**
- **Webhook Integration**: CI/CD systems can POST skill packages to `/scan-upload`
- **REST API Compatibility**: Many CI/CD tools expect REST endpoints
- **Artifact Storage**: Scan results can be stored as build artifacts
- **Example**: GitHub Actions, GitLab CI, Jenkins can easily integrate REST APIs

#### 2. **Web-Based Scanning Interfaces**
- **Upload Interface**: Users can upload ZIP files via web UI
- **Batch Processing**: Web dashboard for scanning multiple skills
- **Result Visualization**: Web-based report viewing
- **Example**: Internal security portal for reviewing skills before deployment

#### 3. **Microservices Architecture**
- **Service Integration**: Other services can call the scanner via HTTP
- **Scalability**: API server can be scaled independently
- **Load Balancing**: Multiple API instances can handle concurrent scans
- **Example**: Skill marketplace that scans uploaded skills automatically

#### 4. **Batch Processing**
- **Async Scanning**: `/scan-batch` endpoint for processing many skills
- **Job Management**: Track scan progress via API
- **Example**: Scanning entire skill repositories overnight

#### 5. **Integration with Other Tools**
- **Security Platforms**: Integration with SIEM, security dashboards
- **Package Managers**: Integration with skill distribution systems
- **Example**: Skill registry that auto-scans new submissions

### Use Cases Where API is NOT Necessary

- **Local Development**: Developers scanning their own skills → Use CLI
- **One-off Scans**: Single skill scan → Use CLI or Python SDK
- **Script Automation**: Python scripts → Use Python SDK directly
- **Simple Workflows**: Basic scanning needs → CLI is sufficient

## Recommendation

### Keep the API Server

**Rationale:**
1. **Low Maintenance Cost**: API server is already implemented and tested
2. **Future-Proofing**: Enables web-based interfaces and integrations
3. **CI/CD Value**: Many teams prefer REST APIs for CI/CD integration
4. **Optional Feature**: Users can choose CLI or API based on their needs
5. **Consistency**: Matches MCP Scanner structure (familiar to users)

### But Make It Optional

**Documentation Should:**
- Emphasize CLI as the primary interface
- Position API as "for CI/CD and integrations"
- Show when to use CLI vs API
- Provide clear examples for both

### Usage Guidelines

**Use CLI when:**
- Scanning local skills during development
- One-off scans or manual testing
- Simple automation scripts
- Direct file system access available

**Use API when:**
- CI/CD pipeline integration
- Web-based scanning interface needed
- Batch processing many skills
- Integration with other services
- Microservices architecture

## Conclusion

**Critical Finding**: Remote skills **do not exist**. Skills are local file packages that users install on their machines, not remote services like MCP servers.

While the API server is **less critical** for Skill Scanner than for MCP Scanner (since there are no remote skills to scan), it still provides value for:
- CI/CD integration (uploading skill ZIP files)
- Web interfaces (uploading skill packages)
- Service integrations (HTTP-based workflows)
- Batch processing (async job management)

**Recommendation**: **Keep the API server** but:
1. Position it as an optional feature for integration use cases
2. Clarify it's for uploading/processing skill ZIP files, NOT for remote skill access
3. Emphasize CLI as the primary interface for most users
4. Remove any references to "scanning remote skills" (they don't exist)

See `docs/remote-skills-analysis.md` for detailed analysis.
