import assert from "node:assert/strict";
import { it } from "vitest";
import { resolvePhysicalHostArchitecture } from "./gondolin-architecture.js";

it("uses physical macOS architecture even when Node runs under Rosetta", () => {
	assert.equal(
		resolvePhysicalHostArchitecture("darwin", "x64", () => "1\n"),
		"aarch64",
	);
	assert.equal(
		resolvePhysicalHostArchitecture("darwin", "arm64", () => "0\n"),
		"x86_64",
	);
});

it("fails closed when the macOS architecture probe fails or is malformed", () => {
	assert.throws(
		() =>
			resolvePhysicalHostArchitecture("darwin", "x64", () => {
				throw new Error("probe failed");
			}),
		/unable to determine physical macOS architecture: probe failed/i,
	);
	assert.throws(
		() => resolvePhysicalHostArchitecture("darwin", "x64", () => "unknown"),
		/unexpected sysctl output/i,
	);
});

it("uses Node architecture on non-macOS hosts", () => {
	assert.equal(
		resolvePhysicalHostArchitecture("linux", "arm64", () => ""),
		"aarch64",
	);
	assert.equal(
		resolvePhysicalHostArchitecture("linux", "x64", () => ""),
		"x86_64",
	);
	assert.throws(
		() => resolvePhysicalHostArchitecture("linux", "ia32", () => ""),
		/unsupported host architecture/i,
	);
});
