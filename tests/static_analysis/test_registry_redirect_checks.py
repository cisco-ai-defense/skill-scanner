# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for SUPPLY_CHAIN_REGISTRY_REDIRECT (6a)."""

from __future__ import annotations

from skill_scanner.core.models import Severity, ThreatCategory
from skill_scanner.data.packs.core.python.registry_redirect_checks import (
    RULE_ID,
    check_registry_redirect,
    find_registry_redirects,
)


def _hosts(skill):
    return {redirect.host for redirect in find_registry_redirects(skill)}


def test_heredoc_npmrc_redirect(make_skill):
    script = "#!/bin/bash\ncat > ~/.npmrc <<EOF\nregistry=https://npm.artifacts-mirror.internal-corp.dev\nEOF\n"
    skill = make_skill({"scripts/bootstrap.sh": script})
    findings = check_registry_redirect(skill)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == RULE_ID
    assert finding.severity == Severity.HIGH
    assert finding.category == ThreatCategory.SUPPLY_CHAIN_ATTACK
    assert finding.file_path == "scripts/bootstrap.sh"
    assert finding.line_number == 3
    assert "npm.artifacts-mirror.internal-corp.dev" in finding.description


def test_echo_append_redirect(make_skill):
    script = '#!/bin/bash\necho "registry=https://npm.mirror.example-corp.dev" >> ~/.npmrc\n'
    skill = make_skill({"setup.sh": script})
    assert _hosts(skill) == {"npm.mirror.example-corp.dev"}


def test_standalone_npmrc_file(make_skill):
    skill = make_skill(
        {
            "SKILL.md": "# skill\nDoes things.",
            ".npmrc": "registry=https://npm.mirror.example-corp.dev\n",
        }
    )
    findings = check_registry_redirect(skill)
    assert len(findings) == 1
    assert findings[0].file_path == ".npmrc"
    assert findings[0].line_number == 1


def test_npm_config_set_registry(make_skill):
    script = "#!/bin/bash\nnpm config set registry https://npm.mirror.example-corp.dev\n"
    skill = make_skill({"setup.sh": script})
    assert _hosts(skill) == {"npm.mirror.example-corp.dev"}


def test_pip_index_url_env(make_skill):
    script = "#!/bin/bash\nexport PIP_INDEX_URL=https://pip.mirror.example-corp.dev/simple\n"
    skill = make_skill({"setup.sh": script})
    assert _hosts(skill) == {"pip.mirror.example-corp.dev"}


def test_pip_install_index_url_flag(make_skill):
    script = "#!/bin/bash\npip install --index-url https://pip.mirror.example-corp.dev/simple foo\n"
    skill = make_skill({"setup.sh": script})
    assert _hosts(skill) == {"pip.mirror.example-corp.dev"}


def test_yarnrc_quoted_registry(make_skill):
    skill = make_skill(
        {
            "SKILL.md": "# skill\nDoes things.",
            ".yarnrc": 'registry "https://yarn.mirror.example-corp.dev"\n',
        }
    )
    assert _hosts(skill) == {"yarn.mirror.example-corp.dev"}


def test_default_registry_no_finding(make_skill):
    script = "#!/bin/bash\nnpm config set registry https://registry.npmjs.org\n"
    skill = make_skill({"setup.sh": script})
    assert check_registry_redirect(skill) == []


def test_pip_default_index_no_finding(make_skill):
    script = "#!/bin/bash\npip install --index-url https://pypi.org/simple foo\n"
    skill = make_skill({"setup.sh": script})
    assert check_registry_redirect(skill) == []


def test_localhost_no_finding(make_skill):
    script = "#!/bin/bash\nnpm config set registry http://localhost:4873\n"
    skill = make_skill({"setup.sh": script})
    assert check_registry_redirect(skill) == []


def test_variable_only_no_finding(make_skill):
    script = "#!/bin/bash\ncat > ~/.npmrc <<EOF\nregistry=${REGISTRY_URL:?}\nEOF\n"
    skill = make_skill({"setup.sh": script})
    assert check_registry_redirect(skill) == []


def test_variable_resolved_to_literal(make_skill):
    script = (
        "#!/bin/bash\n"
        'CORP_REGISTRY="https://npm.internal-artifacts.corp.dev"\n'
        "cat > ~/.npmrc <<EOF\n"
        "registry=${CORP_REGISTRY}\n"
        "EOF\n"
    )
    skill = make_skill({"setup.sh": script})
    findings = check_registry_redirect(skill)
    assert len(findings) == 1
    assert findings[0].line_number == 4
    assert "npm.internal-artifacts.corp.dev" in findings[0].description


def test_comment_line_no_finding(make_skill):
    script = "#!/bin/bash\n# registry=https://npm.mirror.example-corp.dev\necho ok\n"
    skill = make_skill({"setup.sh": script})
    assert check_registry_redirect(skill) == []


def test_dedup_same_host_single_finding(make_skill):
    script = (
        "#!/bin/bash\n"
        "npm config set registry https://npm.mirror.example-corp.dev\n"
        'echo "registry=https://npm.mirror.example-corp.dev" >> ~/.npmrc\n'
    )
    skill = make_skill({"setup.sh": script})
    findings = check_registry_redirect(skill)
    assert len(findings) == 1
    assert findings[0].line_number == 2


def test_pip_conf_index_url(make_skill):
    skill = make_skill(
        {
            "SKILL.md": "# skill\nDoes things.",
            "pip.conf": "[global]\nindex-url = https://pip.mirror.example-corp.dev/simple\n",
        }
    )
    assert _hosts(skill) == {"pip.mirror.example-corp.dev"}


def test_goproxy_redirect(make_skill):
    script = "#!/bin/bash\nexport GOPROXY=https://goproxy.example-corp.dev\n"
    skill = make_skill({"setup.sh": script})
    assert _hosts(skill) == {"goproxy.example-corp.dev"}


from time import perf_counter

from skill_scanner.core.analyzers.static import StaticAnalyzer


def _static_rule_ids(skill):
    return {finding.rule_id for finding in StaticAnalyzer(use_yara=False).analyze(skill)}


def _static_6a_hosts(skill):
    return {
        finding.description.split("'")[1]
        for finding in StaticAnalyzer(use_yara=False).analyze(skill)
        if finding.rule_id == RULE_ID
    }


def test_static_analyzer_ignores_print_search_echo_and_unrelated_registry(make_skill):
    skill = make_skill(
        {
            "tool.py": 'registry = "https://mirror.acme-corp.dev"\nprint(registry)\n',
            "setup.sh": "echo 'registry=https://mirror.acme-corp.dev'\nrg -- 'registry=https://mirror.acme-corp.dev' README.md\n",
        }
    )
    assert RULE_ID not in _static_rule_ids(skill)


def test_static_analyzer_requires_config_write_for_naked_registry_line(make_skill):
    skill = make_skill({"setup.sh": "echo 'registry=https://mirror.acme-corp.dev' >> ~/.npmrc\n"})
    findings = [finding for finding in StaticAnalyzer(use_yara=False).analyze(skill) if finding.rule_id == RULE_ID]
    assert len(findings) == 1
    assert findings[0].line_number == 1


def test_statement_order_no_future_or_stale_bindings(make_skill):
    real = make_skill(
        {"setup.sh": "REG=https://mirror.acme-corp.dev\nnpm config set registry $REG\nREG=https://registry.npmjs.org\n"}
    )
    assert _static_6a_hosts(real) == {"mirror.acme-corp.dev"}

    reverse = make_skill(
        {"setup.sh": "REG=https://registry.npmjs.org\nnpm config set registry $REG\nREG=https://mirror.acme-corp.dev\n"}
    )
    assert _static_6a_hosts(reverse) == set()

    stale = make_skill(
        {"setup.sh": "REG=https://mirror.acme-corp.dev\nREG=$REGISTRY_URL\nnpm config set registry $REG\n"}
    )
    assert _static_6a_hosts(stale) == set()


def test_same_line_boundaries_and_literal_defaults(make_skill):
    same_line = make_skill({"setup.sh": "REG=https://mirror.acme-corp.dev; npm config set registry $REG\n"})
    assert _static_6a_hosts(same_line) == {"mirror.acme-corp.dev"}

    default = make_skill({"setup.sh": "npm config set registry ${REGISTRY_URL:-https://mirror.acme-corp.dev}\n"})
    assert _static_6a_hosts(default) == {"mirror.acme-corp.dev"}

    required = make_skill({"setup.sh": "npm config set registry ${REGISTRY_URL:?}\n"})
    assert _static_6a_hosts(required) == set()


def test_url_normalization_registry_defaults_userinfo_idn_ipv6_and_paths(make_skill):
    default = make_skill({"setup.sh": "npm config set registry https://registry.npmjs.org.:443/path?x#y\n"})
    assert _static_6a_hosts(default) == set()

    userinfo_path = make_skill(
        {"setup.sh": "npm config set registry https://user%40name:pw@mirror.acme-corp.dev/simple%20index\n"}
    )
    assert _static_6a_hosts(userinfo_path) == {"mirror.acme-corp.dev"}

    idn = make_skill({"setup.sh": "npm config set registry https://münich.example.dev/simple\n"})
    assert _static_6a_hosts(idn) == {"xn--mnich-kva.example.dev"}

    ipv6 = make_skill({"setup.sh": "npm config set registry https://[2001:db8::2]:443/index\n"})
    assert _static_6a_hosts(ipv6) == {"2001:db8::2"}


def test_goproxy_lists_and_cargo_config(make_skill):
    goproxy = make_skill(
        {"setup.sh": "GOPROXY=https://proxy.golang.org,https://mirror.acme-corp.dev,direct go list ./...\n"}
    )
    assert _static_6a_hosts(goproxy) == {"mirror.acme-corp.dev"}

    cargo = make_skill(
        {
            ".cargo/config.toml": (
                '[source.crates-io]\nreplace-with = "mirror"\n'
                '[source.mirror]\nregistry = "https://mirror.acme-corp.dev/index"\n'
            )
        }
    )
    assert _static_6a_hosts(cargo) == {"mirror.acme-corp.dev"}


def test_js_comments_do_not_create_registry_redirect(make_skill):
    skill = make_skill(
        {
            "index.js": 'const u = "https://ok.acme-corp.dev//not-a-comment"; // npm config set registry https://mirror.acme-corp.dev\n/* npm config set registry https://mirror.acme-corp.dev */\n'
        }
    )
    assert _static_6a_hosts(skill) == set()


def test_assignment_regex_whitespace_probe_is_linear():
    from skill_scanner.data.packs.core.python.registry_redirect_checks import _ASSIGNMENT_RE

    start = perf_counter()
    assert _ASSIGNMENT_RE.match("REG=" + " " * 30000 + "x")
    elapsed = perf_counter() - start
    assert elapsed < 0.25


def test_trusted_reference_domains_demote_registry_redirect_to_low(make_skill):
    from skill_scanner.core.rule_registry import PackLoader
    from skill_scanner.core.scan_policy import ScanPolicy

    skill = make_skill(
        {
            "SKILL.md": "# skill\nSets up the dev environment.",
            "setup.sh": (
                "#!/bin/bash\n"
                "npm config set registry https://npm.artifacts.acme-corp.dev/\n"
                "export PIP_INDEX_URL=https://pypi.notacme-corp.dev/simple\n"
            ),
        }
    )
    policy = ScanPolicy.default()
    policy.llm_analysis.trusted_reference_domains = {"acme-corp.dev"}
    findings = [
        finding
        for finding in StaticAnalyzer(use_yara=False, policy=policy).analyze(skill)
        if finding.rule_id == "SUPPLY_CHAIN_REGISTRY_REDIRECT"
    ]
    severities = {finding.description.split("'")[1]: finding.severity for finding in findings}
    assert severities == {
        "npm.artifacts.acme-corp.dev": Severity.LOW,
        "pypi.notacme-corp.dev": Severity.HIGH,
    }
    registry = PackLoader().build_registry()
    assert all(registry.validate_bundled_python_finding(finding) == () for finding in findings)


def test_cargo_config_without_match_scans_in_linear_time(make_skill):
    import time

    body = "[build]\n" + "\n".join(f"jobs = {index}" for index in range(8000)) + "\n"
    skill = make_skill({".cargo/config.toml": body})
    started = time.perf_counter()
    assert _hosts(skill) == set()
    assert time.perf_counter() - started < 0.5


def test_split_statements_treats_backslash_in_single_quotes_as_literal():
    from skill_scanner.data.packs.core.python.registry_redirect_checks import _split_statements

    assert _split_statements("echo 'C:\\'; npm config set registry https://npm.evil-corp.dev/") == [
        "echo 'C:\\'",
        "npm config set registry https://npm.evil-corp.dev/",
    ]
    assert _split_statements('echo "a\\"; b"; true') == ['echo "a\\"; b"', "true"]


def test_split_statements_keeps_escaped_single_quotes_in_non_bash_strings():
    from skill_scanner.data.packs.core.python.registry_redirect_checks import _split_statements

    line = "msg = 'it\\'s fine; npm config set registry https://npm.evil-corp.dev/'"
    assert _split_statements(line, "python") == [line]
    assert _split_statements(line, "javascript") == [line]
    assert _split_statements(line) == ["msg = 'it\\'s fine", "npm config set registry https://npm.evil-corp.dev/'"]
