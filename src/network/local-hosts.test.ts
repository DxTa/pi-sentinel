import { describe, expect, it } from "vitest";

import { isLocalHost } from "./local-hosts";

describe("isLocalHost", () => {
  it.each([
    "localhost",
    "LOCALHOST.",
    "mldb.mlp-639-altitude-tad.localhost",
    "127.0.0.1",
    "127.255.0.9",
    "::1",
    "[::1]",
    "host.docker.internal",
    "host.lima.internal",
    "kubernetes.docker.internal",
  ])("treats %s as local", (host) => {
    expect(isLocalHost(host)).toBe(true);
  });

  it.each([
    "example.com",
    "localhost.example.com",
    "evil.localhost.example.com",
    "128.0.0.1",
    "127.0.0.256",
    "10.0.0.5",
    "api.docker.io",
  ])("does not treat %s as local", (host) => {
    expect(isLocalHost(host)).toBe(false);
  });
});
