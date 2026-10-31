import { describe, expect, it, vi } from "vitest";

import { diagnoseLinuxSandbox, type LinuxSandboxDoctorDeps } from "./linux-sandbox-doctor.js";
import type { SrtStatus } from "./srt-status.js";

function status(overrides: Partial<SrtStatus> = {}): SrtStatus {
  return {
    available: true,
    platform: "linux",
    packageAvailable: true,
    entrypointPath: "/helper.mjs",
    entrypointExists: true,
    dependencyChecks: [
      { name: "rg", available: true },
      { name: "bwrap", available: true },
      { name: "socat", available: true },
    ],
    ...overrides,
  };
}

function deps(files: Record<string, string>, probe: string | null = null): LinuxSandboxDoctorDeps {
  return {
    readFile: (path) => files[path] ?? null,
    probeBwrap: vi.fn(() => probe),
    resolveBwrapPath: () => "/usr/bin/bwrap",
  };
}

const UBUNTU = 'NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\n';
const SYSCTL = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";

describe("diagnoseLinuxSandbox", () => {
  it("returns nothing off Linux", () => {
    expect(diagnoseLinuxSandbox(status({ platform: "darwin" }), deps({}))).toEqual([]);
  });

  it("returns nothing when the bwrap probe succeeds", () => {
    expect(diagnoseLinuxSandbox(status(), deps({ "/etc/os-release": UBUNTU, [SYSCTL]: "1\n" }))).toEqual([]);
  });

  it.each([
    [UBUNTU, "Fix: sudo apt install bubblewrap socat"],
    ['ID="fedora"\n', "Fix: sudo dnf install bubblewrap socat"],
    ["ID=arch\n", "Fix: sudo pacman -S bubblewrap socat"],
    ['ID="opensuse-tumbleweed"\nID_LIKE="opensuse suse"\n', "Fix: sudo zypper install bubblewrap socat"],
    ["ID=nixos\n", "Fix: install bubblewrap socat with your package manager."],
  ])("prints the install command for missing packages (%#)", (osRelease, expected) => {
    const doctorDeps = deps({ "/etc/os-release": osRelease });
    const result = diagnoseLinuxSandbox(status({
      available: false,
      dependencyChecks: [
        { name: "rg", available: true },
        { name: "bwrap", available: false },
        { name: "socat", available: false },
      ],
    }), doctorDeps);
    expect(result).toEqual([expected]);
    expect(doctorDeps.probeBwrap).not.toHaveBeenCalled();
  });

  it("prints a bwrap-only AppArmor profile when the userns restriction blocks the probe", () => {
    const result = diagnoseLinuxSandbox(
      status(),
      deps({ "/etc/os-release": UBUNTU, [SYSCTL]: "1\n" }, "bwrap: setting up uid map: Permission denied"),
    );
    const text = result.join("\n");
    expect(text).toContain("bwrap test failed: bwrap: setting up uid map: Permission denied");
    expect(text).toContain("profile bwrap /usr/bin/bwrap flags=(unconfined)");
    expect(text).toContain("sudo apparmor_parser -r /etc/apparmor.d/bwrap");
    expect(text).not.toContain("sysctl -w");
  });

  it("reports other probe failures without the AppArmor fix", () => {
    const result = diagnoseLinuxSandbox(status(), deps({ [SYSCTL]: "0\n" }, "bwrap: No permissions to create new namespace"));
    expect(result[0]).toBe("bwrap test failed: bwrap: No permissions to create new namespace");
    expect(result.join("\n")).not.toContain("apparmor");
  });
});
