import assert from "node:assert/strict";
import { access, mkdtemp, readdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { it } from "vitest";
import {
  createUvDependencyArtifactPreparation,
  parseUvLockArtifacts,
} from "./gondolin-artifacts.js";

const sha256 = `sha256:${"a".repeat(64)}`;

it("parses uv wheel records regardless of field order", () => {
  const hash = "sha256:" + "a".repeat(64);
  const artifacts = parseUvLockArtifacts(`[[package]]
name = "ai-platform-gcputils"
wheels = [{ hash = "${hash}", size = 9218, url = "https://europe-north1-python.pkg.dev/ai-lab-training/internal-python/ai-platform-gcputils/ai_platform_gcputils-0.1.5-py3-none-any.whl" }]
`, "aarch64-unknown-linux-gnu");

  assert.deepEqual(artifacts, [{
    kind: "wheel",
    url: "https://europe-north1-python.pkg.dev/ai-lab-training/internal-python/ai-platform-gcputils/ai_platform_gcputils-0.1.5-py3-none-any.whl",
    hash,
  }]);
});

it("keeps all locked distributions for uv to select inside the guest", () => {
  const artifacts = parseUvLockArtifacts(`[[package]]
name = "pkg"
sdist = { url = "https://files.pythonhosted.org/packages/pkg-1.0.tar.gz", hash = "${sha256}" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/pkg-1.0-cp313-cp313-manylinux_2_28_x86_64.whl", hash = "${sha256}" },
    { url = "https://files.pythonhosted.org/packages/pkg-1.0-cp313-cp313-manylinux_2_28_aarch64.whl", hash = "${sha256}" },
]
`, "aarch64-unknown-linux-gnu");

  assert.equal(artifacts.length, 3);
  assert.deepEqual(artifacts.map(({ kind, url }) => ({ kind, url })), [
    { kind: "sdist", url: "https://files.pythonhosted.org/packages/pkg-1.0.tar.gz" },
    { kind: "wheel", url: "https://files.pythonhosted.org/packages/pkg-1.0-cp313-cp313-manylinux_2_28_x86_64.whl" },
    { kind: "wheel", url: "https://files.pythonhosted.org/packages/pkg-1.0-cp313-cp313-manylinux_2_28_aarch64.whl" },
  ]);
});

it("parses uv.lock with host Python and stages locked public artifacts", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-artifacts-test-"));
  try {
    await writeFile(join(root, "uv.lock"), `[[package]]
name = "pkg"
wheels = [{ url = "https://files.pythonhosted.org/packages/pkg-1.0-py3-none-any.whl", hash = "sha256:c7c5c1d70c5dec4416ab6158afd0b223ef40c29b1dc1f97ed9428b94d4cadb1c" }]
`);
    const preparation = await createUvDependencyArtifactPreparation({
      workspaceRoot: root,
      target: "aarch64-unknown-linux-gnu",
      tempRoot: root,
      fetchArtifact: async () => new Response(Buffer.from("artifact")),
    });
    assert.ok(preparation);
    assert.deepEqual(await readdir(preparation.mounts[0].hostRoot), ["pkg-1.0-py3-none-any.whl"]);
    await preparation.cleanup();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

it("prepares brokered uv registry auth without exposing the token to the guest", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-artifacts-test-"));
  try {
    await writeFile(join(root, "uv.lock"), "lock\n");
    const preparation = await createUvDependencyArtifactPreparation({
      workspaceRoot: root,
      target: "aarch64-unknown-linux-gnu",
      mode: "brokered-network",
      trustedArtifactOrigins: [
        { hostname: "europe-north1-python.pkg.dev", pathPrefix: "/ai-lab-training/internal-python/" },
      ],
      trustedWorkspaceRoots: [root],
      parseLock: async () => [{
        kind: "wheel",
        url: "https://europe-north1-python.pkg.dev/ai-lab-training/internal-python/pkg/pkg-1.0-py3-none-any.whl",
        hash: sha256,
      }],
      runHostCommand: async () => ({ stdout: "token-from-gcloud\n", stderr: "" }),
      fetchArtifact: async () => { throw new Error("brokered mode must not prefetch artifacts"); },
    });

    assert.ok(preparation);
    assert.deepEqual(preparation.mounts, []);
    assert.deepEqual(preparation.environment, {
      UV_CACHE_DIR: "/tmp/pi-uv-cache",
      UV_INDEX: "gondolin-private=https://europe-north1-python.pkg.dev/ai-lab-training/internal-python/simple/",
      UV_INDEX_GONDOLIN_PRIVATE_USERNAME: "oauth2accesstoken",
      UV_INDEX_STRATEGY: "first-index",
      UV_LINK_MODE: "copy",
      UV_LOCKED: "1",
      UV_PROJECT_ENVIRONMENT: "/tmp/pi-uv-venv",
    });
    assert.equal(preparation.environment.UV_INDEX_GONDOLIN_PRIVATE_PASSWORD, undefined);
    assert.deepEqual(preparation.secrets?.map(({ name, value, hosts, pathPrefixes }) => ({ name, value, hosts, pathPrefixes })), [{
      name: "UV_INDEX_GONDOLIN_PRIVATE_PASSWORD",
      value: "token-from-gcloud",
      hosts: ["europe-north1-python.pkg.dev"],
      pathPrefixes: ["/ai-lab-training/internal-python/"],
    }]);
    await preparation.cleanup();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

it("fetches private artifacts with host-only gcloud auth and returns read-only VM settings", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-artifacts-test-"));
  try {
    await writeFile(join(root, "uv.lock"), "lock\n");
    const calls: Array<{ command: string; args: readonly string[] }> = [];
    let receivedAuthorization = "";
    const preparation = await createUvDependencyArtifactPreparation({
      workspaceRoot: root,
      target: "aarch64-unknown-linux-gnu",
      tempRoot: root,
      trustedArtifactOrigins: [
        { hostname: "europe-north1-python.pkg.dev", pathPrefix: "/ai-lab-training/internal-python/" },
      ],
      trustedWorkspaceRoots: [root],
      parseLock: async () => [
        { kind: "wheel", url: "https://europe-north1-python.pkg.dev/ai-lab-training/internal-python/pkg/pkg-1.0-py3-none-any.whl", hash: "sha256:c7c5c1d70c5dec4416ab6158afd0b223ef40c29b1dc1f97ed9428b94d4cadb1c" },
      ],
      runHostCommand: async (command, args) => {
        calls.push({ command, args });
        return { stdout: "token-from-gcloud\n", stderr: "" };
      },
      fetchArtifact: async (_url, init) => {
        receivedAuthorization = String(init?.headers && new Headers(init.headers).get("authorization"));
        return new Response(Buffer.from("artifact"));
      },
    });

    assert.ok(preparation);
    assert.deepEqual(calls, [{ command: "gcloud", args: ["auth", "print-access-token"] }]);
    assert.equal(receivedAuthorization, "Bearer token-from-gcloud");
    assert.deepEqual(preparation.environment, {
      UV_CACHE_DIR: "/tmp/pi-uv-cache",
      UV_FIND_LINKS: "/mnt/pi-uv-artifacts",
      UV_LINK_MODE: "copy",
      UV_LOCKED: "1",
      UV_NO_INDEX: "1",
      UV_OFFLINE: "1",
      UV_PROJECT_ENVIRONMENT: "/tmp/pi-uv-venv",
    });
    assert.deepEqual(await readdir(preparation.mounts[0].hostRoot), ["pkg-1.0-py3-none-any.whl"]);
    assert.equal(await readFile(join(preparation.mounts[0].hostRoot, "pkg-1.0-py3-none-any.whl"), "utf8"), "artifact");
    await preparation.cleanup();
    await assert.rejects(access(preparation.mounts[0].hostRoot));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

it("does not use host credentials for an otherwise approved private registry in an untrusted workspace", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-artifacts-test-"));
  let authCalls = 0;
  try {
    await writeFile(join(root, "uv.lock"), "lock\n");
    await assert.rejects(
      createUvDependencyArtifactPreparation({
        workspaceRoot: root,
        target: "aarch64-unknown-linux-gnu",
        tempRoot: root,
        trustedArtifactOrigins: [
          { hostname: "europe-north1-python.pkg.dev", pathPrefix: "/ai-lab-training/internal-python/" },
        ],
        parseLock: async () => [
          {
            kind: "wheel",
            url: "https://europe-north1-python.pkg.dev/ai-lab-training/internal-python/pkg/pkg-1.0-py3-none-any.whl",
            hash: "sha256:c7c5c1d70c5dec4416ab6158afd0b223ef40c29b1dc1f97ed9428b94d4cadb1c",
          },
        ],
        runHostCommand: async () => {
          authCalls += 1;
          return { stdout: "token\n", stderr: "" };
        },
      }),
      /explicit trust/i,
    );
    assert.equal(authCalls, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

it("rejects a symlinked uv.lock before reading outside the workspace", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-artifacts-test-"));
  const outside = await mkdtemp(join(tmpdir(), "pi-artifacts-outside-"));
  try {
    await writeFile(join(outside, "uv.lock"), "lock\n");
    await symlink(join(outside, "uv.lock"), join(root, "uv.lock"));
    await assert.rejects(
      createUvDependencyArtifactPreparation({ workspaceRoot: root, target: "aarch64-unknown-linux-gnu" }),
      /ELOOP|symlink|operation not permitted/i,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

it("rejects unapproved artifact registries before using host credentials", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-artifacts-test-"));
  try {
    await writeFile(join(root, "uv.lock"), "lock\n");
    await assert.rejects(
      createUvDependencyArtifactPreparation({
        workspaceRoot: root,
        target: "aarch64-unknown-linux-gnu",
        parseLock: async () => [{ kind: "wheel", url: "https://attacker.example/packages/pkg-py3-none-any.whl", hash: sha256 }],
        runHostCommand: async () => { throw new Error("must not run"); },
        fetchArtifact: async () => { throw new Error("must not fetch"); },
      }),
      /not an approved registry path/i,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

it("rejects registry path-prefix lookalikes", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-artifacts-test-"));
  try {
    await writeFile(join(root, "uv.lock"), "lock\n");
    await assert.rejects(
      createUvDependencyArtifactPreparation({
        workspaceRoot: root,
        target: "aarch64-unknown-linux-gnu",
        trustedArtifactOrigins: [{ hostname: "registry.example", pathPrefix: "/approved" }],
        parseLock: async () => [{ kind: "wheel", url: "https://registry.example/approved-evil/pkg-py3-none-any.whl", hash: sha256 }],
        fetchArtifact: async () => { throw new Error("must not fetch"); },
      }),
      /not an approved registry path/i,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

it("skips projects without uv.lock", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-artifacts-test-"));
  try {
    const preparation = await createUvDependencyArtifactPreparation({
      workspaceRoot: root,
      target: "aarch64-unknown-linux-gnu",
      runHostCommand: async () => { throw new Error("must not run"); },
    });
    assert.equal(preparation, undefined);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

it("rejects a downloaded artifact whose hash does not match the lock", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-artifacts-test-"));
  try {
    await writeFile(join(root, "uv.lock"), "lock\n");
    await assert.rejects(
      createUvDependencyArtifactPreparation({
        workspaceRoot: root,
        target: "aarch64-unknown-linux-gnu",
        tempRoot: root,
        parseLock: async () => [{ kind: "wheel", url: "https://files.pythonhosted.org/packages/pkg-1.0-py3-none-any.whl", hash: sha256 }],
        fetchArtifact: async () => new Response(Buffer.from("wrong")),
      }),
      /hash mismatch/i,
    );
    const entries = await readdir(root);
    assert.deepEqual(entries, ["uv.lock"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
