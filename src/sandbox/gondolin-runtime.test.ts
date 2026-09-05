import assert from "node:assert/strict";
import { link, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { it } from "vitest";
import { decideGondolinVfsAccess, isGondolinSensitivePath, type GondolinVfsPolicy } from "./gondolin-policy.js";
import { gondolinReadOnlySourceIdentity, type GondolinPolicyWorkspaceMount } from "./gondolin-session.js";
import {
  createNativeGondolinRuntime,
  detectPhysicalHostArchitecture,
  networkRequest,
  selectGondolinVmm,
  validateGondolinSecretScopes,
} from "./gondolin-runtime.js";

const runRealVm = process.env.PI_GONDOLIN_REAL_TEST === "1";
const image = process.env.PI_GONDOLIN_TEST_IMAGE ?? "3cd7a864-f023-5a35-9db1-39a1be5bdcca";

it("requires explicit QEMU policy for cross-architecture images", () => {
  assert.throws(() => selectGondolinVmm("aarch64", "x86_64"), /gondolinEmulation.*qemu/i);
  assert.deepEqual(selectGondolinVmm("aarch64", "x86_64", "qemu"), {
    emulated: true,
    vmm: "qemu",
    accel: "tcg",
    cpu: "max",
  });
  assert.deepEqual(selectGondolinVmm("aarch64", "aarch64", "deny", "linux"), { emulated: false });
  assert.deepEqual(selectGondolinVmm("aarch64", "aarch64", "deny", "darwin"), {
    emulated: false,
    vmm: "qemu",
    accel: "hvf",
    cpu: "max",
  });
});

it("detects physical macOS architecture instead of trusting Rosetta process.arch", () => {
  const arch = detectPhysicalHostArchitecture();
  assert.ok(arch === "aarch64" || arch === "x86_64");
});

it("rejects ambiguous scoped credentials on one registry host", () => {
  assert.throws(() => validateGondolinSecretScopes([
    { name: "A", value: "a", hosts: ["registry.example.com"], pathPrefixes: ["/a/"] },
    { name: "B", value: "b", hosts: ["registry.example.com"], pathPrefixes: ["/b/"] },
  ]), /cannot share host/);
});

it("restricts brokered registry requests to read-only approved paths", () => {
  const workspace = workspaceMount({ workspaceRoot: "/tmp", sensitivePaths: [] });
  workspace.network.request = () => ({ decision: "allow", domain: "example.com", reason: "test allow" });
  const secret = {
    name: "TOKEN",
    value: "host-secret",
    hosts: ["registry.example.com"],
    pathPrefixes: ["/approved/"],
  };
  assert.equal(networkRequest(new Request("https://registry.example.com/approved/simple/pkg/"), workspace, [secret]), true);
  assert.equal(networkRequest(new Request("https://registry.example.com/approved/upload/", { method: "POST" }), workspace, [secret]), false);
  assert.equal(networkRequest(new Request("https://registry.example.com/other/pkg/"), workspace, [secret]), false);
  assert.equal(networkRequest(new Request("https://registry.example.com/approved/%2e%2e/private/"), workspace, [secret]), false);
});

function workspaceMount(policy: GondolinVfsPolicy): GondolinPolicyWorkspaceMount {
  return {
    kind: "gondolin-policy-vfs",
    isSensitivePath: (path) => isGondolinSensitivePath(policy, path),
    vfs: {
      read: (request) => decideGondolinVfsAccess(policy, request),
      mutate: (request) => decideGondolinVfsAccess(policy, request),
    },
    network: {
      request: () => ({ decision: "deny", domain: null, reason: "test denies network" }),
      tcp: () => ({ decision: "deny", domain: null, reason: "test denies tcp" }),
    },
  };
}

it.skipIf(!runRealVm)("passes secret placeholders to every guest command", { timeout: 30_000 }, async () => {
  const root = await mkdtemp(join(tmpdir(), "gondolin-runtime-secret-"));
  let session: Awaited<ReturnType<ReturnType<typeof createNativeGondolinRuntime>["createSession"]>>;
  try {
    const policy: GondolinVfsPolicy = { workspaceRoot: root, sensitivePaths: [] };
    const runtime = createNativeGondolinRuntime({ workspaceRoot: root });
    session = await runtime.createSession({
      image,
      secrets: [{ name: "UV_INDEX_GONDOLIN_PRIVATE_PASSWORD", value: "host-secret", hosts: ["example.com"] }],
      workspace: workspaceMount(policy),
    });
    if (!session?.operations) throw new Error("Gondolin runtime did not expose operations");
    const output: Buffer[] = [];
    const result = await session.operations.exec("printf '%s' \\\"$UV_INDEX_GONDOLIN_PRIVATE_PASSWORD\\\"", "/workspace", {
      onData: (data) => output.push(data),
    });
    assert.equal(result.exitCode, 0);
    const guestSecret = Buffer.concat(output).toString();
    assert.notEqual(guestSecret, "host-secret");
    assert.match(guestSecret, /GONDOLIN_SECRET_[A-Za-z0-9]+/);
  } finally {
    await session?.close();
    await rm(root, { recursive: true, force: true });
  }
});

it.skipIf(!runRealVm)("native Gondolin runtime executes against a policy-backed workspace", { timeout: 30_000 }, async () => {
  const root = await mkdtemp(join(tmpdir(), "gondolin-runtime-"));
  const globalRoot = await mkdtemp(join(tmpdir(), "gondolin-runtime-home-"));
  const dynamicRoot = await mkdtemp(join(tmpdir(), "gondolin-runtime-dynamic-"));
  const dynamicOutside = await mkdtemp(join(tmpdir(), "gondolin-runtime-dynamic-outside-"));
  let session: Awaited<ReturnType<ReturnType<typeof createNativeGondolinRuntime>["createSession"]>>;
  try {
    await writeFile(join(root, "plain.txt"), "plain\n");
    await writeFile(join(root, ".env"), "SECRET=never-leak\n");
    await writeFile(join(globalRoot, ".npmrc"), "//registry.example/:_authToken=never-leak\n");
    await mkdir(join(globalRoot, "cache"), { recursive: true });
    await writeFile(join(globalRoot, "cache", "tool.txt"), "cached\n");
    await writeFile(join(dynamicRoot, "tool.txt"), "dynamic\n");
    await writeFile(join(dynamicRoot, ".env"), "dynamic-secret\n");
    await link(join(dynamicRoot, ".env"), join(dynamicRoot, "hardlink.txt"));
    await writeFile(join(dynamicOutside, "secret.txt"), "outside\n");
    await writeFile(join(dynamicOutside, "outside-sensitive.txt"), "outside-sensitive\n");
    await link(join(dynamicOutside, "outside-sensitive.txt"), join(dynamicRoot, "outside-hardlink.txt"));
    await symlink("tool.txt", join(dynamicRoot, "alias.txt"));
    await symlink(dynamicOutside, join(dynamicRoot, "escape"));
    await link(join(root, ".env"), join(root, "alias.txt"));
    const policy: GondolinVfsPolicy = { workspaceRoot: root, sensitivePaths: ["**/.env"] };
    const globalPolicy: GondolinVfsPolicy = { workspaceRoot: globalRoot, sensitivePaths: [".npmrc"] };
    const runtime = createNativeGondolinRuntime({ workspaceRoot: root, memory: "512M", cpus: 1 });
    session = await runtime.createSession({
      image,
      secrets: [{ name: "TEST_TOKEN", value: "host-secret", hosts: ["example.com"] }],
      workspace: workspaceMount(policy),
      mounts: [{ guestPath: "/root", hostRoot: globalRoot, readOnly: true, workspace: workspaceMount(globalPolicy) }],
    });
    if (!session?.operations) throw new Error("Gondolin runtime did not expose operations");
    const operations = session.operations;
    if (!session.addReadOnlySource) throw new Error("Gondolin runtime dynamic source capability is unavailable");
    const dynamicGuestPath = await session.addReadOnlySource({
      hostRoot: dynamicRoot,
      workspace: workspaceMount({ workspaceRoot: dynamicRoot, sensitivePaths: ["**/.env"] }),
      identity: gondolinReadOnlySourceIdentity(dynamicRoot),
    });
    assert.equal((await operations.fs.readFile(`${dynamicGuestPath}/tool.txt`)).toString(), "dynamic\n");
    assert.equal((await operations.fs.readFile(`${dynamicGuestPath}/alias.txt`)).toString(), "dynamic\n");
    assert.equal((await operations.fs.readFile(`${dynamicGuestPath}/hardlink.txt`)).toString(), "(masked)");
    assert.equal((await operations.fs.readFile(`${dynamicGuestPath}/outside-hardlink.txt`)).toString(), "(masked)");

    const output: Buffer[] = [];
    const result = await operations.exec("cat /workspace/plain.txt", "/workspace", {
      onData: (data) => output.push(data),
    });
    assert.equal(result.exitCode, 0);
    assert.equal(Buffer.concat(output).toString(), "plain\n");
    assert.equal((await operations.fs.readFile("/workspace/plain.txt")).toString(), "plain\n");

    const masked = await operations.fs.readFile("/workspace/.env");
    assert.equal(masked.toString(), "(masked)");
    assert.equal((await operations.fs.readFile("/workspace/alias.txt")).toString(), "(masked)");
    const statOutput: Buffer[] = [];
    const statResult = await operations.exec("stat -c '%s:%u:%g:%a' /workspace/.env /workspace/alias.txt", "/workspace", {
      onData: (data) => statOutput.push(data),
    });
    assert.equal(statResult.exitCode, 0);
    assert.equal(Buffer.concat(statOutput).toString(), "8:0:0:444\n8:0:0:444\n");
    const envOutput: Buffer[] = [];
    await operations.exec("env", "/workspace", {
      env: { SECRET_TOKEN: "never-forward", LANG: "C" },
      onData: (data) => envOutput.push(data),
    });
    assert.doesNotMatch(Buffer.concat(envOutput).toString(), /SECRET_TOKEN=never-forward/);
    const secretOutput: Buffer[] = [];
    await operations.exec("printf '%s' \\\"$TEST_TOKEN\\\"", "/workspace", {
      onData: (data) => secretOutput.push(data),
    });
    const guestSecret = Buffer.concat(secretOutput).toString();
    assert.notEqual(guestSecret, "host-secret");
    assert.match(guestSecret, /GONDOLIN_SECRET_[A-Za-z0-9]+/);

    const maskedExec = await operations.exec("cat /workspace/.env", "/workspace", { onData: () => {} });
    assert.equal(maskedExec.exitCode, 0);

    await operations.fs.writeFile("/workspace/write.txt", "workspace-write\n");
    assert.equal((await operations.fs.readFile("/workspace/write.txt")).toString(), "workspace-write\n");
    assert.equal((await operations.fs.readFile("/root/cache/tool.txt")).toString(), "cached\n");
    assert.equal((await operations.fs.readFile("/root/.npmrc")).toString(), "(masked)");
    const globalWrite = await operations.exec("echo blocked > /root/cache/new.txt", "/workspace", {
      onData: () => {},
    });
    assert.notEqual(globalWrite.exitCode, 0);
    const dynamicEscape = await operations.exec(`cat ${dynamicGuestPath}/escape/secret.txt`, "/workspace", {
      onData: () => {},
    });
    assert.notEqual(dynamicEscape.exitCode, 0);
    const dynamicWrite = await operations.exec(`echo blocked > ${dynamicGuestPath}/new.txt`, "/workspace", {
      onData: () => {},
    });
    assert.notEqual(dynamicWrite.exitCode, 0);
    for (const command of [
      `touch ${dynamicGuestPath}/created.txt`,
      `rm ${dynamicGuestPath}/tool.txt`,
      `mv ${dynamicGuestPath}/tool.txt ${dynamicGuestPath}/moved.txt`,
    ]) {
      const mutation = await operations.exec(command, "/workspace", { onData: () => {} });
      assert.notEqual(mutation.exitCode, 0);
    }
    assert.equal((await readFile(join(dynamicRoot, "tool.txt"))).toString(), "dynamic\n");
  } finally {
    await session?.close();
    await rm(root, { recursive: true, force: true });
    await rm(globalRoot, { recursive: true, force: true });
    await rm(dynamicRoot, { recursive: true, force: true });
    await rm(dynamicOutside, { recursive: true, force: true });
  }
});

it.skipIf(!runRealVm)("keeps fixed approved mount paths isolated across parallel VMs", { timeout: 60_000 }, async () => {
  const workspaceA = await mkdtemp(join(tmpdir(), "gondolin-runtime-parallel-a-"));
  const workspaceB = await mkdtemp(join(tmpdir(), "gondolin-runtime-parallel-b-"));
  const sourceA = await mkdtemp(join(tmpdir(), "gondolin-runtime-source-a-"));
  const sourceB = await mkdtemp(join(tmpdir(), "gondolin-runtime-source-b-"));
  let sessionA: Awaited<ReturnType<ReturnType<typeof createNativeGondolinRuntime>["createSession"]>>;
  let sessionB: Awaited<ReturnType<ReturnType<typeof createNativeGondolinRuntime>["createSession"]>>;
  try {
    await writeFile(join(sourceA, "file.txt"), "A\n");
    await writeFile(join(sourceB, "file.txt"), "B\n");
    const create = (workspaceRoot: string) => createNativeGondolinRuntime({ workspaceRoot, memory: "512M", cpus: 1 }).createSession({
      image,
      workspace: workspaceMount({ workspaceRoot }),
    });
    [sessionA, sessionB] = await Promise.all([create(workspaceA), create(workspaceB)]);
    if (!sessionA?.operations || !sessionA.addReadOnlySource || !sessionB?.operations || !sessionB.addReadOnlySource) {
      throw new Error("Gondolin runtime dynamic source capability is unavailable");
    }
    const [guestA, guestB] = await Promise.all([
      sessionA.addReadOnlySource({
        hostRoot: sourceA,
        workspace: workspaceMount({ workspaceRoot: sourceA }),
        identity: gondolinReadOnlySourceIdentity(sourceA),
      }),
      sessionB.addReadOnlySource({
        hostRoot: sourceB,
        workspace: workspaceMount({ workspaceRoot: sourceB }),
        identity: gondolinReadOnlySourceIdentity(sourceB),
      }),
    ]);
    assert.equal(guestA, "/mnt/approved/m1");
    assert.equal(guestB, "/mnt/approved/m1");
    assert.equal((await sessionA.operations.fs.readFile(`${guestA}/file.txt`)).toString(), "A\n");
    assert.equal((await sessionB.operations.fs.readFile(`${guestB}/file.txt`)).toString(), "B\n");
    await expectMissing(sessionA.operations.fs.readFile(`${guestA}/missing-from-b.txt`));
    await sessionA.close();
    assert.equal((await sessionB.operations.fs.readFile(`${guestB}/file.txt`)).toString(), "B\n");
  } finally {
    await sessionA?.close();
    await sessionB?.close();
    await rm(workspaceA, { recursive: true, force: true });
    await rm(workspaceB, { recursive: true, force: true });
    await rm(sourceA, { recursive: true, force: true });
    await rm(sourceB, { recursive: true, force: true });
  }
});

async function expectMissing(operation: Promise<unknown>): Promise<void> {
  try {
    await operation;
    assert.fail("expected guest path to be absent");
  } catch (error) {
    assert.match(String(error), /FileNotFound|ENOENT|not found/i);
  }
}
