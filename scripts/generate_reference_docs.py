#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Generate reference documentation pages from source of truth.

This script keeps key reference pages synchronized with live source code.
"""

from __future__ import annotations

import argparse
import ast
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REFERENCE_DIR = ROOT / "docs" / "reference"

GENERATED_BANNER = (
    "<!-- GENERATED FILE. DO NOT EDIT DIRECTLY.\n"
    "     Regenerate with: uv run python scripts/generate_reference_docs.py -->\n\n"
)


@dataclass(frozen=True)
class HelpBlock:
    title: str
    command: list[str]


def _run_python_module_help(module_and_args: list[str]) -> str:
    cmd = [sys.executable, *module_and_args]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"Command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr}")
    return proc.stdout.strip()


def _render_cli_reference() -> str:
    blocks = [
        HelpBlock("Top-level CLI", ["-m", "skill_scanner.cli.cli", "--help"]),
        HelpBlock("scan", ["-m", "skill_scanner.cli.cli", "scan", "--help"]),
        HelpBlock("scan-all", ["-m", "skill_scanner.cli.cli", "scan-all", "--help"]),
        HelpBlock("validate-rules", ["-m", "skill_scanner.cli.cli", "validate-rules", "--help"]),
        HelpBlock("generate-policy", ["-m", "skill_scanner.cli.cli", "generate-policy", "--help"]),
        HelpBlock("configure-policy", ["-m", "skill_scanner.cli.cli", "configure-policy", "--help"]),
        HelpBlock("API server CLI", ["-m", "skill_scanner.api.api_cli", "--help"]),
        HelpBlock("Pre-commit hook CLI", ["-m", "skill_scanner.hooks.pre_commit", "--help"]),
    ]

    sections: list[str] = [
        "# CLI Command Reference",
        "",
        "This page is generated from live `argparse` output and should match runtime behavior exactly.",
        "",
        "## At a Glance",
        "",
        "| Command | Purpose | Example |",
        "|---|---|---|",
        "| `skill-scanner scan` | Scan a single skill package | `skill-scanner scan ./my-skill` |",
        "| `skill-scanner scan-all` | Scan multiple skill packages | `skill-scanner scan-all ./skills/ -r` |",
        "| `skill-scanner list-analyzers` | Show available analyzers | `skill-scanner list-analyzers` |",
        "| `skill-scanner validate-rules` | Validate YAML rule signatures | `skill-scanner validate-rules` |",
        "| `skill-scanner generate-policy` | Generate a policy YAML file | `skill-scanner generate-policy --preset strict` |",
        "| `skill-scanner configure-policy` | Interactive TUI policy editor | `skill-scanner configure-policy` |",
        "| `skill-scanner interactive` | Interactive setup wizard | `skill-scanner interactive` |",
        "| `skill-scanner-api` | Start the REST API server | `skill-scanner-api --port 8080` |",
        "| `skill-scanner-pre-commit` | Git pre-commit hook | `skill-scanner-pre-commit install` |",
        "",
        "## Common Flags",
        "",
        "Flags shared by `scan` and `scan-all`:",
        "",
        "| Flag | Default | Description |",
        "|---|---|---|",
        "| `--format FORMAT` | `summary` | Output format: `summary`, `json`, `markdown`, `table`, `sarif`, `html` |",
        "| `--output FILE` | stdout | Write output to a file instead of stdout |",
        "| `--policy POLICY` | `balanced` | Policy preset name or path to a custom YAML |",
        "| `--use-llm` | off | Enable the LLM semantic analyzer |",
        "| `--use-behavioral` | off | Enable the behavioral analyzer |",
        "| `--use-virustotal` | off | Enable VirusTotal hash lookups |",
        "| `--use-aidefense` | off | Enable Cisco AI Defense analyzer |",
        "| `--enable-meta` | off | Enable the meta (cross-correlation) analyzer |",
        "| `--fail-on-findings` | off | Exit non-zero if critical or high findings are reported; equivalent to `--fail-on-severity high` (CI gate) |",
        "| `--fail-on-severity LEVEL` | off | Exit non-zero if findings at or above LEVEL exist (critical, high, medium, low, info) |",
        "| `--lenient` | off | Tolerate malformed skills: coerce bad fields, fill defaults, and continue instead of failing |",
        "| `--detailed` | off | Include full evidence in output |",
        "| `--compact` | off | Minimize output (JSON: no pretty-print) |",
        "| `--verbose` | off | Verbose logging |",
        "",
    ]

    for block in blocks:
        output = _run_python_module_help(block.command)
        command_text = "python " + " ".join(block.command)
        sections.extend(
            [
                f"## {block.title}",
                "",
                f"Command: `{command_text}`",
                "",
                "<details>",
                f"<summary>Full <code>{block.title.lower()}</code> help output</summary>",
                "",
                "```text",
                output,
                "```",
                "",
                "</details>",
                "",
            ]
        )

    return GENERATED_BANNER + "\n".join(sections).rstrip() + "\n"


@dataclass(frozen=True)
class Endpoint:
    method: str
    path: str
    handler: str
    response_model: str
    summary: str


def _extract_endpoints(router_path: Path) -> list[Endpoint]:
    module = ast.parse(router_path.read_text(encoding="utf-8"))
    endpoints: list[Endpoint] = []

    for node in module.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        doc = ast.get_docstring(node) or ""
        summary = doc.splitlines()[0].strip() if doc else ""

        for deco in node.decorator_list:
            if not isinstance(deco, ast.Call):
                continue
            if not isinstance(deco.func, ast.Attribute):
                continue
            if not isinstance(deco.func.value, ast.Name) or deco.func.value.id != "router":
                continue
            if deco.func.attr not in {"get", "post", "put", "patch", "delete"}:
                continue

            path = ""
            if deco.args and isinstance(deco.args[0], ast.Constant) and isinstance(deco.args[0].value, str):
                path = deco.args[0].value

            response_model = ""
            for kw in deco.keywords:
                if kw.arg == "response_model":
                    try:
                        response_model = ast.unparse(kw.value)
                    except Exception:
                        response_model = "<complex>"
                    break

            endpoints.append(
                Endpoint(
                    method=deco.func.attr.upper(),
                    path=path,
                    handler=node.name,
                    response_model=response_model or "-",
                    summary=summary or "-",
                )
            )

    return sorted(endpoints, key=lambda e: (e.path, e.method))


@dataclass(frozen=True)
class ModelField:
    name: str
    annotation: str


@dataclass(frozen=True)
class PydanticModel:
    name: str
    fields: list[ModelField]


def _extract_pydantic_models(router_path: Path) -> list[PydanticModel]:
    module = ast.parse(router_path.read_text(encoding="utf-8"))
    models: list[PydanticModel] = []

    for node in module.body:
        if not isinstance(node, ast.ClassDef):
            continue

        base_names: set[str] = set()
        for base in node.bases:
            try:
                base_names.add(ast.unparse(base))
            except Exception:
                continue

        if not any(name.endswith("BaseModel") or name == "BaseModel" for name in base_names):
            continue

        fields: list[ModelField] = []
        for stmt in node.body:
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                fname = stmt.target.id
                try:
                    annotation = ast.unparse(stmt.annotation)
                except Exception:
                    annotation = "<unknown>"
                fields.append(ModelField(name=fname, annotation=annotation))

        models.append(PydanticModel(name=node.name, fields=fields))

    return models


def _render_api_reference() -> str:
    router_path = ROOT / "skill_scanner" / "api" / "router.py"
    endpoints = _extract_endpoints(router_path)
    models = _extract_pydantic_models(router_path)

    sections: list[str] = [
        "# API Endpoint Reference",
        "",
        "This page is generated from `skill_scanner/api/router.py`.",
        "",
        "> [!TIP]",
        "> **Interactive Docs**",
        "> Start the API server with `skill-scanner-api` and open `/docs` (Swagger UI) or `/redoc` for interactive exploration.",
        "",
        "> [!NOTE]",
        "> **Full details**",
        "> For complete request/response schemas, parameter descriptions, and edge-case guidance, see the hand-written [API Endpoints Detail](../user-guide/api-endpoints-detail.md).",
        "",
        "## Endpoints",
        "",
        "| Method | Path | Response Model | Description |",
        "|---|---|---|---|",
    ]

    for ep in endpoints:
        desc = ep.summary if ep.summary != "-" else ""
        sections.append(f"| `{ep.method}` | `{ep.path}` | `{ep.response_model}` | {desc} |")

    sections.extend(
        [
            "",
            "## Quick Examples",
            "",
            "### Health check",
            "",
            "```bash",
            "curl http://localhost:8000/health",
            "```",
            "",
            "```json",
            "{",
            '  "status": "healthy",',
            '  "version": "1.0.0",',
            '  "analyzers_available": ["static_analyzer", "bytecode_analyzer", "pipeline_analyzer"]',
            "}",
            "```",
            "",
            "### Scan a skill",
            "",
            "```bash",
            "curl -X POST http://localhost:8000/scan \\",
            "  -H 'Content-Type: application/json' \\",
            "  -d '{",
            '    "skill_directory": "/path/to/my-skill",',
            '    "use_llm": false,',
            '    "policy": "balanced"',
            "  }'",
            "```",
            "",
            "```json",
            "{",
            '  "scan_id": "a1b2c3d4",',
            '  "skill_name": "my-skill",',
            '  "is_safe": false,',
            '  "max_severity": "HIGH",',
            '  "findings_count": 3,',
            '  "scan_duration_seconds": 1.42,',
            '  "timestamp": "2025-01-15T10:30:00Z",',
            '  "findings": [{"...": "..."}]',
            "}",
            "```",
            "",
            "### Upload and scan",
            "",
            "```bash",
            "curl -X POST http://localhost:8000/scan-upload \\",
            "  -F 'file=@my-skill.zip'",
            "```",
            "",
        ]
    )

    sections.extend(["## Request/Response Models", ""])

    for model in models:
        sections.append(f"### `{model.name}`")
        sections.append("")
        if not model.fields:
            sections.append("No typed fields discovered.")
            sections.append("")
            continue

        sections.append("| Field | Type |")
        sections.append("|---|---|")
        for field in model.fields:
            sections.append(f"| `{field.name}` | `{field.annotation}` |")
        sections.append("")

    sections.extend(
        [
            "## Notes",
            "",
            "- API behavior is policy-aware and mirrors CLI analyzer selection flags.",
            "- API keys for VirusTotal and AI Defense are passed via request headers (`X-VirusTotal-Key`, `X-AIDefense-Key`), not in the JSON body.",
            "- Set `SKILL_SCANNER_ALLOWED_ROOTS` to restrict which directories the API can scan.",
            "- All `POST` endpoints accept JSON bodies. File upload uses `multipart/form-data`.",
        ]
    )

    return GENERATED_BANNER + "\n".join(sections).rstrip() + "\n"


def _collect_env_variables() -> dict[str, set[str]]:
    env_map: dict[str, set[str]] = {}

    def add(var: str, source: str) -> None:
        env_map.setdefault(var, set()).add(source)

    env_file = ROOT / ".env.example"
    env_assign_re = re.compile(r"^\s*#?\s*([A-Z][A-Z0-9_]+)\s*=")
    for line in env_file.read_text(encoding="utf-8").splitlines():
        m = env_assign_re.match(line)
        if m:
            add(m.group(1), ".env.example")

    candidates = [
        ROOT / "skill_scanner" / "config" / "config.py",
        ROOT / "skill_scanner" / "cli" / "cli.py",
        ROOT / "skill_scanner" / "api" / "router.py",
        ROOT / "skill_scanner" / "core" / "analyzers" / "llm_analyzer.py",
        ROOT / "skill_scanner" / "core" / "analyzer_factory.py",
        ROOT / "skill_scanner" / "core" / "analyzers" / "llm_provider_config.py",
        ROOT / "skill_scanner" / "core" / "analyzers" / "behavioral_analyzer.py",
        ROOT / "skill_scanner" / "core" / "analyzers" / "aidefense_analyzer.py",
        ROOT / "skill_scanner" / "core" / "analyzers" / "meta_analyzer.py",
        ROOT / "skill_scanner" / "threats" / "cisco_ai_taxonomy.py",
        ROOT / "skill_scanner" / "threats" / "threats.py",
    ]

    env_get_re = re.compile(r'os\.(?:getenv|environ\.get)\(\s*"([A-Z][A-Z0-9_]+)"')
    env_const_re = re.compile(r'^(_?[A-Z][A-Z0-9_]+)\s*(?::\s*str\s*)?=\s*"([A-Z][A-Z0-9_]+)"', re.MULTILINE)
    for path in candidates:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        rel = str(path.relative_to(ROOT))
        for var in env_get_re.findall(text):
            add(var, rel)
        for const_name, var_value in env_const_re.findall(text):
            if re.search(rf"os\.(?:getenv|environ\.get)\(\s*{const_name}", text):
                add(var_value, rel)

    return dict(sorted(env_map.items()))


def _describe_env_var(var: str) -> str:
    descriptions = {
        "SKILL_SCANNER_LLM_API_KEY": "Primary API key for LLM analyzer and meta fallback.",
        "SKILL_SCANNER_LLM_MODEL": "Primary model identifier for semantic analysis.",
        "SKILL_SCANNER_LLM_BASE_URL": "Optional custom endpoint base URL for provider routing.",
        "SKILL_SCANNER_LLM_API_VERSION": "Optional API version for providers that require one.",
        "SKILL_SCANNER_META_LLM_API_KEY": "Meta-analyzer API key override.",
        "SKILL_SCANNER_META_LLM_MODEL": "Meta-analyzer model override.",
        "SKILL_SCANNER_META_LLM_BASE_URL": "Meta-analyzer base URL override.",
        "SKILL_SCANNER_META_LLM_API_VERSION": "Meta-analyzer API version override.",
        "VIRUSTOTAL_API_KEY": "VirusTotal analyzer API key.",
        "VIRUSTOTAL_UPLOAD_FILES": "Enable upload mode for unknown binaries.",
        "AI_DEFENSE_API_KEY": "Cisco AI Defense analyzer API key.",
        "AI_DEFENSE_API_URL": "Cisco AI Defense endpoint override.",
        "AWS_REGION": "AWS region for Bedrock-backed flows.",
        "AWS_PROFILE": "AWS credential profile for Bedrock IAM auth.",
        "AWS_SESSION_TOKEN": "Optional AWS session token.",
        "GOOGLE_APPLICATION_CREDENTIALS": "Path to GCP service account credentials.",
        "SKILL_SCANNER_ALLOWED_ROOTS": "Colon-delimited API path allowlist for server-side path access.",
        "SKILL_SCANNER_TAXONOMY_PATH": "Path to a custom Cisco AI taxonomy YAML file (overridden by `--taxonomy`).",
        "SKILL_SCANNER_THREAT_MAPPING_PATH": "Path to a custom threat mapping YAML file (overridden by `--threat-mapping`).",
        "GEMINI_API_KEY": "Google AI Studio key; auto-set from `SKILL_SCANNER_LLM_API_KEY` when using Gemini via LiteLLM.",
        "ENABLE_STATIC_ANALYZER": "Optional environment toggle for static analyzer default.",
        "ENABLE_LLM_ANALYZER": "Optional environment toggle for LLM analyzer default.",
        "ENABLE_BEHAVIORAL_ANALYZER": "Optional environment toggle for behavioral analyzer default.",
        "ENABLE_AIDEFENSE": "Optional environment toggle for AI Defense analyzer default.",
    }
    return descriptions.get(var, "Configuration variable discovered in source code.")


_ENV_VAR_GROUPS: list[tuple[str, str, list[str]]] = [
    (
        "LLM Configuration",
        "Primary settings for the LLM semantic analyzer.",
        [
            "SKILL_SCANNER_LLM_API_KEY",
            "SKILL_SCANNER_LLM_MODEL",
            "SKILL_SCANNER_LLM_BASE_URL",
            "SKILL_SCANNER_LLM_API_VERSION",
        ],
    ),
    (
        "Meta Analyzer",
        "Override LLM settings for the meta (cross-correlation) analyzer. Falls back to the primary LLM values.",
        [
            "SKILL_SCANNER_META_LLM_API_KEY",
            "SKILL_SCANNER_META_LLM_MODEL",
            "SKILL_SCANNER_META_LLM_BASE_URL",
            "SKILL_SCANNER_META_LLM_API_VERSION",
        ],
    ),
    (
        "AWS / Bedrock",
        "Required when using a `bedrock/...` model with IAM credentials instead of an API key.",
        ["AWS_REGION", "AWS_PROFILE", "AWS_SESSION_TOKEN"],
    ),
    (
        "Google / Vertex",
        "Credentials for Vertex AI and Google AI Studio.",
        ["GOOGLE_APPLICATION_CREDENTIALS", "GEMINI_API_KEY"],
    ),
    (
        "VirusTotal",
        "Enable the VirusTotal hash-lookup analyzer.",
        ["VIRUSTOTAL_API_KEY", "VIRUSTOTAL_UPLOAD_FILES"],
    ),
    (
        "Cisco AI Defense",
        "Enable the Cisco AI Defense cloud analyzer.",
        ["AI_DEFENSE_API_KEY", "AI_DEFENSE_API_URL"],
    ),
    (
        "Feature Toggles",
        "Override default analyzer enablement via environment. Values: `true`/`1` or `false`/`0`.",
        [
            "ENABLE_STATIC_ANALYZER",
            "ENABLE_LLM_ANALYZER",
            "ENABLE_BEHAVIORAL_ANALYZER",
            "ENABLE_AIDEFENSE",
        ],
    ),
    (
        "Advanced",
        "Paths, allowlists, and other advanced settings.",
        [
            "SKILL_SCANNER_ALLOWED_ROOTS",
            "SKILL_SCANNER_TAXONOMY_PATH",
            "SKILL_SCANNER_THREAT_MAPPING_PATH",
        ],
    ),
]

_ENV_VAR_EXAMPLES: dict[str, str] = {
    "SKILL_SCANNER_LLM_API_KEY": "sk-ant-...",
    "SKILL_SCANNER_LLM_MODEL": "anthropic/claude-sonnet-4-20250514",
    "SKILL_SCANNER_LLM_BASE_URL": "https://api.openai.com/v1",
    "SKILL_SCANNER_LLM_API_VERSION": "2024-02-15-preview",
    "SKILL_SCANNER_META_LLM_API_KEY": "(falls back to LLM_API_KEY)",
    "SKILL_SCANNER_META_LLM_MODEL": "(falls back to LLM_MODEL)",
    "SKILL_SCANNER_META_LLM_BASE_URL": "(falls back to LLM_BASE_URL)",
    "SKILL_SCANNER_META_LLM_API_VERSION": "(falls back to LLM_API_VERSION)",
    "AWS_REGION": "us-east-1",
    "AWS_PROFILE": "my-bedrock-profile",
    "AWS_SESSION_TOKEN": "(temporary STS token)",
    "GOOGLE_APPLICATION_CREDENTIALS": "/path/to/sa-key.json",
    "GEMINI_API_KEY": "(auto-set from LLM_API_KEY)",
    "VIRUSTOTAL_API_KEY": "(your VT key)",
    "VIRUSTOTAL_UPLOAD_FILES": "false",
    "AI_DEFENSE_API_KEY": "(your AI Defense key)",
    "AI_DEFENSE_API_URL": "https://us.api.inspect.aidefense.security.cisco.com/api/v1",
    "ENABLE_STATIC_ANALYZER": "true",
    "ENABLE_LLM_ANALYZER": "false",
    "ENABLE_BEHAVIORAL_ANALYZER": "false",
    "ENABLE_AIDEFENSE": "false",
    "SKILL_SCANNER_ALLOWED_ROOTS": "/srv/skills:/home/user/skills",
    "SKILL_SCANNER_TAXONOMY_PATH": "/path/to/taxonomy.yaml",
    "SKILL_SCANNER_THREAT_MAPPING_PATH": "/path/to/threats.yaml",
}

_ENV_VAR_REQUIRED: set[str] = {"SKILL_SCANNER_LLM_API_KEY"}


def _render_configuration_reference() -> str:
    env_map = _collect_env_variables()
    grouped_vars: set[str] = set()
    for _, _, vars_ in _ENV_VAR_GROUPS:
        grouped_vars.update(vars_)

    sections: list[str] = [
        "# Configuration Reference",
        "",
        "This page is generated from `.env.example` and runtime source references.",
        "",
        "> [!TIP]",
        "> **Quick Start**",
        "> Most users only need to set one or two variables. Create a `.env` file in your project root:",
        ">",
        "> ```bash",
        "> # Minimal .env for Anthropic",
        '> SKILL_SCANNER_LLM_API_KEY="sk-ant-..."',
        '> SKILL_SCANNER_LLM_MODEL="anthropic/claude-sonnet-4-20250514"',
        "> ```",
        ">",
        "> See [Installation and Configuration](../user-guide/installation-and-configuration.md) for provider-specific setup.",
        "",
    ]

    for group_title, group_desc, group_vars in _ENV_VAR_GROUPS:
        sections.extend(
            [
                f"## {group_title}",
                "",
                group_desc,
                "",
                "| Variable | Description | Example |",
                "|---|---|---|",
            ]
        )
        for var in group_vars:
            if var not in env_map:
                continue
            desc = _describe_env_var(var).replace("|", "\\|")
            req = " **(required)**" if var in _ENV_VAR_REQUIRED else ""
            example = _ENV_VAR_EXAMPLES.get(var, "")
            example_cell = f"`{example}`" if example else ""
            sections.append(f"| `{var}` | {desc}{req} | {example_cell} |")
        sections.append("")

    ungrouped = {v: s for v, s in env_map.items() if v not in grouped_vars}
    if ungrouped:
        sections.extend(["## Other", "", "| Variable | Description | Example |", "|---|---|---|"])
        for var, _sources in sorted(ungrouped.items()):
            desc = _describe_env_var(var).replace("|", "\\|")
            example = _ENV_VAR_EXAMPLES.get(var, "")
            example_cell = f"`{example}`" if example else ""
            sections.append(f"| `{var}` | {desc} | {example_cell} |")
        sections.append("")

    sections.extend(
        [
            "<details>",
            "<summary>Source file mapping</summary>",
            "",
            "| Variable | Source(s) |",
            "|---|---|",
        ]
    )
    for var, sources in sorted(env_map.items()):
        src = ", ".join(f"`{s}`" for s in sorted(sources))
        sections.append(f"| `{var}` | {src} |")
    sections.extend(
        [
            "",
            "</details>",
            "",
            "## Related",
            "",
            "- CLI flags: [CLI Command Reference](cli-command-reference.md)",
            "- Policy YAML: [Custom Policy Configuration](../user-guide/custom-policy-configuration.md)",
            "- Presets: [Scan Policies Overview](../user-guide/scan-policies-overview.md)",
        ]
    )

    return GENERATED_BANNER + "\n".join(sections).rstrip() + "\n"


def _generate_all() -> dict[Path, str]:
    return {
        REFERENCE_DIR / "cli-command-reference.md": _render_cli_reference(),
        REFERENCE_DIR / "api-endpoint-reference.md": _render_api_reference(),
        REFERENCE_DIR / "configuration-reference.md": _render_configuration_reference(),
    }


def _write_or_check(outputs: dict[Path, str], check: bool) -> int:
    failures = 0
    for path, content in outputs.items():
        if check:
            existing = path.read_text(encoding="utf-8") if path.exists() else ""
            if existing != content:
                print(f"OUTDATED: {path}")
                failures += 1
            continue

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        print(f"WROTE: {path}")

    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate reference docs from source of truth.")
    parser.add_argument("--check", action="store_true", help="Fail if generated outputs differ from committed files")
    args = parser.parse_args()

    outputs = _generate_all()
    return _write_or_check(outputs, check=args.check)


if __name__ == "__main__":
    raise SystemExit(main())
