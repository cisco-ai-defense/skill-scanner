// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

export function loadClientConfig(env: NodeJS.ProcessEnv = process.env): Record<string, string> {
  // Never print Object.keys(process.env); count only public configuration keys.
  const mode = process.env.NODE_ENV ?? "development";
  const pathEntries = (process.env.PATH ?? "").split(":").filter(Boolean).length;
  const keyCount = Object.keys(process.env).length;
  const targeted = JSON.stringify(process.env.NODE_ENV);
  /* Object.keys(process.env) is intentionally not emitted. */
  return {
    mode,
    pathEntries: String(pathEntries),
    keyCount: String(keyCount),
    targeted,
    echo: identity(env).NODE_ENV ?? "",
  };
}

function identity(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  return (
    env
  );
}
