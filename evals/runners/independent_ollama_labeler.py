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

"""Reproducible, scanner-independent labeling through a local Ollama daemon.

This adapter is intentionally incompatible with the sealed Hugging Face
benchmark schema. It accepts only explicitly unlabeled supplemental cases,
never scanner findings, and emits a separate provenance-rich labeling report.
Two independently requested passes must agree on a non-abstain label before a
case is accepted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

SCHEMA_VERSION = 1
EVALUATION_TRACK = "model_labeled_supplemental"
LABELS = frozenset({"benign", "malicious", "contextual_risk", "abstain"})
_HEX = frozenset("0123456789abcdef")
_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "corpus_id",
        "evaluation_track",
        "contains_authoritative_labels",
        "model",
        "rubric",
        "prompt",
        "passes",
        "cases",
    }
)
_MODEL_FIELDS = frozenset({"name", "digest"})
_TEXT_FIELDS = frozenset({"text", "sha256"})
_PASS_FIELDS = frozenset({"pass_id", "seed"})
_CASE_FIELDS = frozenset({"case_id", "content", "content_sha256", "label_status", "sealed_labeled_test"})
_MAX_MANIFEST_BYTES = 128 * 1024 * 1024
_MAX_CASES = 10_000
_MAX_CONTENT_BYTES = 2 * 1024 * 1024
_MAX_TOTAL_CONTENT_BYTES = 128 * 1024 * 1024
_MAX_RUBRIC_BYTES = 64 * 1024
_MAX_PROMPT_BYTES = 32 * 1024
_MAX_RESPONSE_BYTES = 1024 * 1024


class IndependentLabelingError(ValueError):
    """Raised when labeling evidence cannot be trusted."""


class LabelProvider(Protocol):
    def model_digest(self, model: str) -> str: ...

    def label(
        self,
        *,
        model: str,
        rendered_prompt: str,
        rubric: str,
        seed: int,
    ) -> Mapping[str, Any]: ...


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _digest(value: Any, location: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(character not in _HEX for character in value):
        raise IndependentLabelingError(f"{location} must be a lowercase SHA-256 digest")
    return value


def _string(value: Any, location: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value:
        raise IndependentLabelingError(f"{location} must be a non-empty string")
    if len(value.encode("utf-8")) > maximum:
        raise IndependentLabelingError(f"{location} exceeds its {maximum}-byte bound")
    return value


def _exact_mapping(value: Any, fields: frozenset[str], location: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise IndependentLabelingError(f"{location} must contain exactly {sorted(fields)}")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise IndependentLabelingError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise IndependentLabelingError(f"non-finite JSON number is forbidden: {value}")


def _decode_json(raw: str | bytes, location: str) -> Any:
    try:
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise IndependentLabelingError(f"invalid {location} JSON: {exc}") from exc


def _read_manifest(path: Path) -> Mapping[str, Any]:
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise IndependentLabelingError("labeling manifest must be a regular non-symlink file")
    if source.stat().st_size > _MAX_MANIFEST_BYTES:
        raise IndependentLabelingError("labeling manifest exceeds its bounded size")
    try:
        value = _decode_json(source.read_text(encoding="utf-8"), "labeling manifest")
    except OSError as exc:
        raise IndependentLabelingError(f"cannot read labeling manifest: {exc}") from exc
    return _exact_mapping(value, _MANIFEST_FIELDS, "manifest")


def _validate_manifest(value: Mapping[str, Any]) -> dict[str, Any]:
    if value.get("schema_version") != SCHEMA_VERSION:
        raise IndependentLabelingError("manifest uses an unsupported schema_version")
    corpus_id = _string(value.get("corpus_id"), "manifest.corpus_id", maximum=1024)
    if value.get("evaluation_track") != EVALUATION_TRACK:
        raise IndependentLabelingError(f"manifest.evaluation_track must be {EVALUATION_TRACK!r}")
    if value.get("contains_authoritative_labels") is not False:
        raise IndependentLabelingError("manifest must contain only otherwise-unlabeled cases")

    model = _exact_mapping(value.get("model"), _MODEL_FIELDS, "manifest.model")
    model_name = _string(model.get("name"), "manifest.model.name", maximum=512)
    model_digest = _digest(model.get("digest"), "manifest.model.digest")

    rubric = _exact_mapping(value.get("rubric"), _TEXT_FIELDS, "manifest.rubric")
    rubric_text = _string(rubric.get("text"), "manifest.rubric.text", maximum=_MAX_RUBRIC_BYTES)
    rubric_digest = _digest(rubric.get("sha256"), "manifest.rubric.sha256")
    if _sha256_text(rubric_text) != rubric_digest:
        raise IndependentLabelingError("manifest.rubric.sha256 does not match rubric text")

    prompt = _exact_mapping(value.get("prompt"), _TEXT_FIELDS, "manifest.prompt")
    prompt_text = _string(prompt.get("text"), "manifest.prompt.text", maximum=_MAX_PROMPT_BYTES)
    prompt_digest = _digest(prompt.get("sha256"), "manifest.prompt.sha256")
    if _sha256_text(prompt_text) != prompt_digest:
        raise IndependentLabelingError("manifest.prompt.sha256 does not match prompt text")
    if prompt_text.count("{rubric}") != 1 or prompt_text.count("{content}") != 1:
        raise IndependentLabelingError("prompt must contain exactly one {rubric} and one {content} placeholder")
    residual = prompt_text.replace("{rubric}", "").replace("{content}", "").replace("{case_id}", "")
    if "{" in residual or "}" in residual:
        raise IndependentLabelingError("prompt contains an unsupported placeholder")

    raw_passes = value.get("passes")
    if not isinstance(raw_passes, list) or len(raw_passes) != 2:
        raise IndependentLabelingError("manifest.passes must contain exactly two independent passes")
    passes: list[dict[str, Any]] = []
    pass_ids: set[str] = set()
    seeds: set[int] = set()
    for index, raw_pass in enumerate(raw_passes):
        item = _exact_mapping(raw_pass, _PASS_FIELDS, f"manifest.passes[{index}]")
        pass_id = _string(item.get("pass_id"), f"manifest.passes[{index}].pass_id", maximum=128)
        seed = item.get("seed")
        if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed <= 2**31 - 1:
            raise IndependentLabelingError(f"manifest.passes[{index}].seed must be a bounded integer")
        if pass_id in pass_ids or seed in seeds:
            raise IndependentLabelingError("the two labeling passes must have distinct IDs and seeds")
        pass_ids.add(pass_id)
        seeds.add(seed)
        passes.append({"pass_id": pass_id, "seed": seed})

    raw_cases = value.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases or len(raw_cases) > _MAX_CASES:
        raise IndependentLabelingError(f"manifest.cases must contain between 1 and {_MAX_CASES} cases")
    cases: list[dict[str, Any]] = []
    case_ids: set[str] = set()
    total_bytes = 0
    for index, raw_case in enumerate(raw_cases):
        case = _exact_mapping(raw_case, _CASE_FIELDS, f"manifest.cases[{index}]")
        case_id = _string(case.get("case_id"), f"manifest.cases[{index}].case_id", maximum=512)
        if case_id in case_ids:
            raise IndependentLabelingError(f"duplicate case_id: {case_id}")
        case_ids.add(case_id)
        content = _string(case.get("content"), f"manifest.cases[{index}].content", maximum=_MAX_CONTENT_BYTES)
        total_bytes += len(content.encode("utf-8"))
        if total_bytes > _MAX_TOTAL_CONTENT_BYTES:
            raise IndependentLabelingError("manifest case content exceeds the aggregate byte bound")
        content_digest = _digest(case.get("content_sha256"), f"manifest.cases[{index}].content_sha256")
        if _sha256_text(content) != content_digest:
            raise IndependentLabelingError(f"manifest.cases[{index}].content_sha256 does not match content")
        if case.get("label_status") != "unlabeled":
            raise IndependentLabelingError("model labeling accepts only label_status='unlabeled'")
        if case.get("sealed_labeled_test") is not False:
            raise IndependentLabelingError("sealed labeled test cases must never enter model labeling")
        cases.append({"case_id": case_id, "content": content, "content_sha256": content_digest})

    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
    input_set = json.dumps(
        [{"case_id": case["case_id"], "content_sha256": case["content_sha256"]} for case in cases],
        sort_keys=True,
        separators=(",", ":"),
    )
    return {
        "corpus_id": corpus_id,
        "manifest_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "input_set_sha256": hashlib.sha256(
            b"skill-scanner-independent-label-inputs-v1\0" + input_set.encode("utf-8")
        ).hexdigest(),
        "model": {"name": model_name, "digest": model_digest},
        "rubric": {"text": rubric_text, "sha256": rubric_digest},
        "prompt": {"text": prompt_text, "sha256": prompt_digest},
        "passes": passes,
        "cases": cases,
    }


def _validate_label(value: Mapping[str, Any], location: str) -> dict[str, Any]:
    if set(value) != {"label", "rationale_codes"}:
        raise IndependentLabelingError(f"{location} must contain exactly label and rationale_codes")
    label = value.get("label")
    if label not in LABELS:
        raise IndependentLabelingError(f"{location}.label must be one of {sorted(LABELS)}")
    codes = value.get("rationale_codes")
    if not isinstance(codes, list) or len(codes) > 32:
        raise IndependentLabelingError(f"{location}.rationale_codes must be a bounded array")
    normalized_codes = [
        _string(code, f"{location}.rationale_codes[{index}]", maximum=128) for index, code in enumerate(codes)
    ]
    if len(normalized_codes) != len(set(normalized_codes)):
        raise IndependentLabelingError(f"{location}.rationale_codes must be duplicate-free")
    return {"label": label, "rationale_codes": sorted(normalized_codes)}


class OllamaProvider:
    """Minimal loopback-only Ollama API client."""

    def __init__(self, base_url: str = "http://127.0.0.1:11434", *, timeout_seconds: float = 120.0):
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "::1"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise IndependentLabelingError("Ollama endpoint must be an HTTP loopback literal with no path")
        if timeout_seconds <= 0:
            raise IndependentLabelingError("Ollama timeout must be positive")
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        # Ignore HTTP(S)_PROXY and hosted-provider environment configuration;
        # this adapter has exactly one loopback transport.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _request(self, path: str, payload: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=body,
            headers={"Content-Type": "application/json"},
            method="GET" if payload is None else "POST",
        )
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
        except (OSError, urllib.error.URLError) as exc:
            raise IndependentLabelingError(f"local Ollama request failed: {exc}") from exc
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise IndependentLabelingError("local Ollama response exceeds its byte bound")
        value = _decode_json(raw, "local Ollama response")
        if not isinstance(value, Mapping):
            raise IndependentLabelingError("local Ollama returned a non-object response")
        return value

    def model_digest(self, model: str) -> str:
        response = self._request("/api/tags")
        models = response.get("models")
        if not isinstance(models, list):
            raise IndependentLabelingError("local Ollama model inventory is invalid")
        for item in models:
            if isinstance(item, Mapping) and item.get("name") == model:
                return _digest(item.get("digest"), f"Ollama model {model!r} digest")
        raise IndependentLabelingError(f"frozen Ollama model is not installed: {model}")

    def label(
        self,
        *,
        model: str,
        rendered_prompt: str,
        rubric: str,
        seed: int,
    ) -> Mapping[str, Any]:
        response = self._request(
            "/api/chat",
            {
                "model": model,
                "stream": False,
                "format": {
                    "type": "object",
                    "properties": {
                        "label": {"type": "string", "enum": sorted(LABELS)},
                        "rationale_codes": {
                            "type": "array",
                            "items": {"type": "string"},
                            "maxItems": 32,
                        },
                    },
                    "required": ["label", "rationale_codes"],
                    "additionalProperties": False,
                },
                "messages": [
                    {"role": "system", "content": rubric},
                    {"role": "user", "content": rendered_prompt},
                ],
                "options": {"temperature": 0, "seed": seed, "num_predict": 256},
            },
        )
        message = response.get("message")
        if not isinstance(message, Mapping) or not isinstance(message.get("content"), str):
            raise IndependentLabelingError("local Ollama response has no message content")
        result = _decode_json(message["content"], "local Ollama label")
        if not isinstance(result, Mapping):
            raise IndependentLabelingError("local Ollama label must be an object")
        return result


def run_independent_labeling(
    manifest_path: Path,
    *,
    provider: LabelProvider | None = None,
    base_url: str = "http://127.0.0.1:11434",
    timeout_seconds: float = 120.0,
) -> dict[str, Any]:
    manifest = _validate_manifest(_read_manifest(manifest_path))
    label_provider = provider or OllamaProvider(base_url, timeout_seconds=timeout_seconds)
    installed_digest = label_provider.model_digest(manifest["model"]["name"])
    if installed_digest != manifest["model"]["digest"]:
        raise IndependentLabelingError("installed Ollama model digest does not match the frozen manifest")

    results: list[dict[str, Any]] = []
    provider_errors = 0
    disagreements = 0
    abstentions = 0
    accepted = 0
    for case in manifest["cases"]:
        rendered = (
            manifest["prompt"]["text"]
            .replace("{rubric}", manifest["rubric"]["text"])
            .replace("{content}", case["content"])
            .replace("{case_id}", case["case_id"])
        )
        pass_results: list[dict[str, Any]] = []
        for pass_config in manifest["passes"]:
            try:
                raw_label = label_provider.label(
                    model=manifest["model"]["name"],
                    rendered_prompt=rendered,
                    rubric=manifest["rubric"]["text"],
                    seed=pass_config["seed"],
                )
                label = _validate_label(raw_label, f"case {case['case_id']} pass {pass_config['pass_id']}")
                pass_results.append(
                    {
                        **pass_config,
                        "request_sha256": _sha256_text(rendered),
                        **label,
                        "error": None,
                    }
                )
            except Exception as exc:
                provider_errors += 1
                pass_results.append(
                    {
                        **pass_config,
                        "request_sha256": _sha256_text(rendered),
                        "label": "abstain",
                        "rationale_codes": [],
                        "error": str(exc),
                    }
                )
        labels = [item["label"] for item in pass_results]
        agreement = labels[0] == labels[1]
        accepted_label = labels[0] if agreement and labels[0] != "abstain" else "abstain"
        if accepted_label == "abstain":
            abstentions += 1
        else:
            accepted += 1
        if not agreement:
            disagreements += 1
        results.append(
            {
                "case_id": case["case_id"],
                "content_sha256": case["content_sha256"],
                "accepted_label": accepted_label,
                "agreement": agreement,
                "passes": pass_results,
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "status": "passed" if provider_errors == 0 else "failed",
        "evaluation_track": EVALUATION_TRACK,
        "authoritative_hf_metrics_eligible": False,
        "scanner_outputs_used_as_labels": False,
        "identity": {
            "corpus_id": manifest["corpus_id"],
            "manifest_sha256": manifest["manifest_sha256"],
            "input_set_sha256": manifest["input_set_sha256"],
            "model_name": manifest["model"]["name"],
            "model_digest": manifest["model"]["digest"],
            "rubric_sha256": manifest["rubric"]["sha256"],
            "prompt_sha256": manifest["prompt"]["sha256"],
            "passes": manifest["passes"],
        },
        "counts": {
            "cases": len(results),
            "accepted": accepted,
            "abstained": abstentions,
            "disagreements": disagreements,
            "provider_errors": provider_errors,
        },
        "cases": results,
    }


def _write_report(path: Path, report: Mapping[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        mode = destination.lstat().st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            raise IndependentLabelingError("output must be a regular non-symlink file")
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("short write while emitting labeling report")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, destination)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Double-pass label otherwise-unlabeled cases with local Ollama")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ollama-base-url", default="http://127.0.0.1:11434")
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = run_independent_labeling(
            args.manifest,
            base_url=args.ollama_base_url,
            timeout_seconds=args.timeout_seconds,
        )
        _write_report(args.output, report)
    except (IndependentLabelingError, OSError, TypeError, KeyError) as exc:
        print(f"independent labeling failed: {exc}", file=sys.stderr)
        return 2
    if report["status"] != "passed":
        print(f"independent labeling incomplete; see {args.output}", file=sys.stderr)
        return 1
    print(f"independent labeling report written to {args.output}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
