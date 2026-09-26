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

"""Materialize the fixed real-skill sample a pull-request detection check scans.

    python evals/datasets/materialize_clawhub_sample.py --source-dir RAW --clean-root CLEAN --size 2000

``RAW`` holds the lock-pinned ``data/validation.jsonl`` downloaded at its pinned revision. The file
is hash-verified against the dataset lock and the raw-snapshot contract before any row is read;
the sample is written label-free, for flag rates only.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from evals.datasets.clawhub_security_signals import (  # noqa: E402
    DATASET_ID,
    ClawhubSecuritySignalsError,
    load_clawhub_security_signals_snapshot,
    materialize_flag_rate_sample,
)
from evals.datasets.public_datasets import (  # noqa: E402
    DatasetLockError,
    DatasetSchemaError,
    get_locked_dataset,
    load_dataset_lock,
    pull_request_acquisition,
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--clean-root", type=Path, required=True)
    parser.add_argument("--corpus", default="clawhub-sample")
    parser.add_argument("--size", type=int, default=2_000)
    args = parser.parse_args(argv)
    try:
        lock = load_dataset_lock()
        revision = str(get_locked_dataset(DATASET_ID, lock)["revision"])
        splits = [str(split) for split in pull_request_acquisition(DATASET_ID, lock)["partitions"]]
        snapshot = load_clawhub_security_signals_snapshot(args.source_dir, revision=revision, splits=splits)
        summary = materialize_flag_rate_sample(snapshot, args.clean_root, corpus=args.corpus, size=args.size)
    except (ClawhubSecuritySignalsError, DatasetLockError, DatasetSchemaError, OSError) as exc:
        print(f"ClawHub sample materialization failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
