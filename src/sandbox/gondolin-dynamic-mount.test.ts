import { afterEach, describe, expect, it } from "vitest";
import type { VirtualProvider } from "@earendil-works/gondolin";
import { DynamicReadOnlyProvider } from "./gondolin-dynamic-mount.js";

const providers: DynamicReadOnlyProvider[] = [];

async function makeSource(content: string, readOnly = true): Promise<VirtualProvider> {
  const { MemoryProvider, VirtualFileSystem } = await import("@earendil-works/gondolin");
  const provider = new MemoryProvider();
  const filesystem = new VirtualFileSystem(provider);
  filesystem.writeFileSync("/file.txt", content);
  if (readOnly) provider.setReadOnly();
  return provider;
}

async function readFile(provider: VirtualProvider, path: string): Promise<Buffer | string> {
  const handle = await provider.open(path, "r");
  try {
    return await handle.readFile();
  } finally {
    await handle.close();
  }
}

afterEach(async () => {
  await Promise.all(providers.splice(0).map((provider) => provider.close()));
});

describe("DynamicReadOnlyProvider", () => {
  it("isolates same guest IDs between provider instances", async () => {
    const first = new DynamicReadOnlyProvider();
    const second = new DynamicReadOnlyProvider();
    providers.push(first, second);

    expect(first.addSource(await makeSource("first"))).toBe("/m1");
    expect(second.addSource(await makeSource("second"))).toBe("/m1");

    expect((await readFile(first, "/m1/file.txt")).toString()).toBe("first");
    expect((await readFile(second, "/m1/file.txt")).toString()).toBe("second");
  });

  it("publishes multiple sources without losing concurrent additions", async () => {
    const provider = new DynamicReadOnlyProvider();
    providers.push(provider);

    const paths = await Promise.all([
      Promise.resolve(provider.addSource(await makeSource("first"))),
      Promise.resolve(provider.addSource(await makeSource("second"))),
    ]);

    expect(paths).toEqual(["/m1", "/m2"]);
    expect((await readFile(provider, "/m1/file.txt")).toString()).toBe("first");
    expect((await readFile(provider, "/m2/file.txt")).toString()).toBe("second");
  });

  it("rejects writable sources before publishing a route", async () => {
    const provider = new DynamicReadOnlyProvider();
    providers.push(provider);
    const writable = await makeSource("unsafe", false);

    expect(() => provider.addSource(writable)).toThrow(/read-only/);
    expect(provider.readdirSync("/")).toEqual([]);
  });

  it("keeps source paths inside opaque child routes", async () => {
    const provider = new DynamicReadOnlyProvider();
    providers.push(provider);
    await provider.addSource(await makeSource("safe"));

    await expect(readFile(provider, "/m1/../../outside")).rejects.toThrow();
    await expect(readFile(provider, "/host-secret/file.txt")).rejects.toThrow();
  });

  it("clears only its own routes on close", async () => {
    const first = new DynamicReadOnlyProvider();
    const second = new DynamicReadOnlyProvider();
    providers.push(first, second);
    await first.addSource(await makeSource("first"));
    await second.addSource(await makeSource("second"));

    await first.close();

    await expect(readFile(first, "/m1/file.txt")).rejects.toThrow(/closed/);
    expect((await readFile(second, "/m1/file.txt")).toString()).toBe("second");
  });
});
