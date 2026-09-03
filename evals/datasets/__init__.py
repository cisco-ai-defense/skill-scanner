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

"""Pinned public-corpus metadata and safe static materialization helpers."""

from evals.datasets.public_datasets import (
    LOCKED_DATASET_IDS,
    DatasetLockError,
    DatasetSchemaError,
    UnsafeSampleError,
    artifact_manifest_sha256,
    get_locked_dataset,
    load_dataset_lock,
    locked_split_protocols,
    materialize_locked_skill_row,
    materialize_skill_files,
    quarantine_manifest_sha256,
    sample_metadata_manifest_sha256,
    validate_artifact_manifest,
    validate_locked_row,
    validate_quarantine_manifest,
    validate_sample_metadata_manifest,
    validate_snapshot_metadata,
    validate_source_artifact_manifest,
    validated_portable_relative_path,
)

__all__ = [
    "LOCKED_DATASET_IDS",
    "DatasetLockError",
    "DatasetSchemaError",
    "UnsafeSampleError",
    "artifact_manifest_sha256",
    "get_locked_dataset",
    "load_dataset_lock",
    "locked_split_protocols",
    "materialize_locked_skill_row",
    "materialize_skill_files",
    "quarantine_manifest_sha256",
    "sample_metadata_manifest_sha256",
    "validate_artifact_manifest",
    "validate_locked_row",
    "validate_quarantine_manifest",
    "validate_sample_metadata_manifest",
    "validate_snapshot_metadata",
    "validate_source_artifact_manifest",
    "validated_portable_relative_path",
]
