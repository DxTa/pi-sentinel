import { execFileSync } from "node:child_process";
import type { Architecture } from "@earendil-works/gondolin";

export type PhysicalArchitectureProbe = () => string;

export function resolvePhysicalHostArchitecture(
	platform: NodeJS.Platform,
	nodeArchitecture: string,
	probe: PhysicalArchitectureProbe,
): Architecture {
	if (platform === "darwin") {
		let arm64Flag: string;
		try {
			arm64Flag = probe().trim();
		} catch (error) {
			throw new Error(
				`Unable to determine physical macOS architecture: ${error instanceof Error ? error.message : String(error)}`,
			);
		}
		if (arm64Flag === "1") return "aarch64";
		if (arm64Flag === "0") return "x86_64";
		throw new Error(
			`Unable to determine physical macOS architecture: unexpected sysctl output ${JSON.stringify(arm64Flag)}`,
		);
	}
	if (nodeArchitecture === "arm64") return "aarch64";
	if (nodeArchitecture === "x64") return "x86_64";
	throw new Error(`Unsupported host architecture: ${nodeArchitecture}`);
}

export function detectPhysicalHostArchitecture(): Architecture {
	return resolvePhysicalHostArchitecture(process.platform, process.arch, () =>
		execFileSync("/usr/sbin/sysctl", ["-in", "hw.optional.arm64"], {
			encoding: "utf8",
		}),
	);
}
