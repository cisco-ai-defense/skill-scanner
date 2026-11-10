# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Regression coverage for bounded Bun.spawnSync signature precision."""

import pytest

from skill_scanner.core.rules.patterns import (
    SIGNATURE_CONTEXT_KINDS,
    SIGNATURE_POLARITIES,
    RuleLoader,
)

SAFE_RESTART = (
    "Bun.spawnSync([process.execPath, ...process.argv.slice(1)], { cwd: process.cwd(), "
    'env: process.env, stdin: "inherit", stdout: "inherit", stderr: "inherit" });'
)


@pytest.fixture(scope="module")
def command_rules():
    return {rule.id: rule for rule in RuleLoader().load_rules()}


@pytest.mark.parametrize(
    "source",
    [
        'const scriptsDirectory = import.meta.dir;\nBun.spawnSync([process.execPath, "install", "--frozen-lockfile"], { cwd: scriptsDirectory });',
        'Bun.spawnSync([process.execPath, ...process.argv.slice(1)], { cwd: process.cwd(), env: process.env, stdin: "inherit", stdout: "inherit", stderr: "inherit" });',
    ],
)
def test_structured_bun_calls_are_not_node_shell_injection(command_rules, source):
    rule = command_rules["COMMAND_INJECTION_JS_CHILD_PROCESS"]
    assert not rule.scan_content(source, "runner.ts")


@pytest.mark.parametrize(
    "source",
    [
        'Bun.spawnSync(["sh", "-c", userInput]);',
        'Bun.spawnSync(["/bin/bash", "-lc", userInput]);',
        'Bun.spawnSync([command, "status"]);',
        'Bun.spawnSync([process.execPath, "-e", userCode]);',
        'Bun.spawnSync({ cmd: ["git", "status"] });',
        'Bun.spawnSync(["git", "-c", "core.sshCommand=sh -c payload"]);',
        'Bun.spawnSync(["git", "-C", repo, ...args], { argv0: other });',
        'Bun.spawnSync(["git", "-C", repo, ...args], { env: { PATH: userPath } });',
        'Bun.spawnSync(["git", "-C", repo, ...args], { ...opts });',
        'Bun.spawnSync(["git", "-C", repo, ...args]);',
        'const SCRIPT = join(import.meta.dir, "orch.ts");\nBun.spawnSync([process.execPath, SCRIPT, ...args], { env });',
        "Bun.spawnSync([process.execPath, SCRIPT, ...args], { env });",
        'Bun.spawnSync([process.execPath, "install", "--frozen-lockfile"], { argv0: "sh" });',
        'Bun.spawnSync([process.execPath, "install", "--frozen-lockfile"], { cwd: scriptsDirectory });',
        'const scriptsDirectory = import.meta.dir;\nBun.spawnSync([process.execPath, "install", "--frozen-lockfile"], { cwd: userDirectory });',
        '/* const scriptsDirectory = import.meta.dir; */\nlet scriptsDirectory = userDirectory;\nBun.spawnSync([process.execPath, "install", "--frozen-lockfile"], { cwd: scriptsDirectory });',
        'const scriptsDirectory = import.meta.dir;\nfunction run(scriptsDirectory) { Bun.spawnSync([process.execPath, "install", "--frozen-lockfile"], { cwd: scriptsDirectory }); }',
        'Bun.spawnSync([process.execPath, ...process.argv.slice(1)], { cwd: process.cwd(), env: userEnv, stdin: "inherit", stdout: "inherit", stderr: "inherit" });',
        'Bun.spawnSync([process.execPath, ...process.argv.slice(1)], { cwd: process.cwd(), env: process.env, stdin: "inherit", stdout: "inherit", stderr: "inherit", argv0: "sh" });',
    ],
)
def test_dangerous_or_unknown_bun_calls_remain_detected(command_rules, source):
    rule = command_rules["COMMAND_INJECTION_JS_CHILD_PROCESS"]
    assert rule.scan_content(source, "runner.ts")


@pytest.mark.parametrize(
    ("source", "call_line"),
    [
        ("const Bun = { spawnSync: evil };\n" + SAFE_RESTART, 2),
        ("function run(Bun) {\n" + SAFE_RESTART + "\n}", 2),
        ("Bun.spawnSync = evil;\n" + SAFE_RESTART, 2),
        ('Bun["spawnSync"] = evil;\n' + SAFE_RESTART, 2),
        ("Object.assign(Bun, { spawnSync: evil });\n" + SAFE_RESTART, 2),
        ("process.execPath = evil;\n" + SAFE_RESTART, 2),
        ("function run(process) {\n" + SAFE_RESTART + "\n}", 2),
        ('globalThis["Bun"] = evil;\n' + SAFE_RESTART, 2),
        ('process["execPath"] = evil;\n' + SAFE_RESTART, 2),
        ("process.env.UNSAFE = userInput;\n" + SAFE_RESTART, 2),
        ('eval("Bun.spawnSync = evil");\n' + SAFE_RESTART, 2),
        ('Object.defineProperty(globalThis, "\\u0042un", { value: { spawnSync: evil } });\n' + SAFE_RESTART, 2),
        ('Reflect.set(globalThis, "\\u0070rocess", { execPath: evil });\n' + SAFE_RESTART, 2),
        ("({}).constructor.constructor(userInput)();\n" + SAFE_RESTART, 2),
        ('globalThis["ev\\al"](userInput);\n' + SAFE_RESTART, 2),
    ],
)
def test_bun_or_process_shadowing_retains_execution_finding(command_rules, source, call_line):
    rule = command_rules["COMMAND_INJECTION_JS_CHILD_PROCESS"]
    assert any(finding["line_number"] == call_line for finding in rule.scan_content(source, "runner.ts"))


def test_bun_bootstrap_and_dynamic_orchestrator_calls(command_rules):
    rule = command_rules["COMMAND_INJECTION_JS_CHILD_PROCESS"]
    bootstrap = """
const scriptsDirectory = import.meta.dir;
const result = Bun.spawnSync(
  [process.execPath, "install", "--frozen-lockfile"],
  { cwd: scriptsDirectory }
);
const restarted = Bun.spawnSync([process.execPath, ...process.argv.slice(1)], {
  cwd: process.cwd(),
  env: process.env,
  stdin: "inherit",
  stdout: "inherit",
  stderr: "inherit",
});
"""
    orchestrator = """
const result = Bun.spawnSync(["git", "-C", repo, ...args]);
const result2 = Bun.spawnSync([process.execPath, SCRIPT, ...args], { env });
"""
    assert not rule.scan_content(bootstrap, "bootstrap.ts")
    assert [finding["line_number"] for finding in rule.scan_content(orchestrator, "orch.test.ts")] == [
        2,
        3,
    ]


def test_safe_bun_call_does_not_hide_node_spawn_on_same_line(command_rules):
    rule = command_rules["COMMAND_INJECTION_JS_CHILD_PROCESS"]
    source = 'const scriptsDirectory = import.meta.dir; Bun.spawnSync([process.execPath, "install", "--frozen-lockfile"], { cwd: scriptsDirectory }); cp.spawnSync("sh", ["-c", input]);'
    findings = rule.scan_content(source, "runner.ts")
    assert len(findings) == 1
    assert findings[0]["matched_pattern"] == r"\bspawnSync\s*\("
    assert findings[0]["pattern_index"] == rule.patterns.index(r"\bspawnSync\s*\(")
    assert source[findings[0]["match_start"] : findings[0]["match_end"]] == "spawnSync("
    assert findings[0]["context_kind"] in SIGNATURE_CONTEXT_KINDS
    assert findings[0]["polarity"] in SIGNATURE_POLARITIES


def test_bun_precision_uses_normalized_offsets_for_crlf(command_rules):
    rule = command_rules["COMMAND_INJECTION_JS_CHILD_PROCESS"]
    source = (
        "const scriptsDirectory = import.meta.dir;\r\n"
        'Bun.spawnSync([process.execPath, "install", "--frozen-lockfile"], { cwd: scriptsDirectory });\r\n'
        'Bun.spawnSync(["git", "-C", repo, ...args]);\r\n'
    )
    findings = rule.scan_content(source, "runner.ts")
    assert [finding["line_number"] for finding in findings] == [3]
    assert findings[0]["pattern_index"] == rule.patterns.index(r"\bspawnSync\s*\(")


def test_bare_node_spawn_sync_still_detected(command_rules):
    rule = command_rules["COMMAND_INJECTION_JS_CHILD_PROCESS"]
    assert rule.scan_content('spawnSync("sh", ["-c", command]);', "runner.ts")


def test_aliased_node_spawn_sync_still_detected(command_rules):
    rule = command_rules["COMMAND_INJECTION_JS_CHILD_PROCESS"]
    assert rule.scan_content('cp.spawnSync("sh", ["-c", command]);', "runner.ts")
