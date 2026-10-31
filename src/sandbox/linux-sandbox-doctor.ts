import { spawnSync } from "node:child_process";
import { readFileSync, realpathSync } from "node:fs";

import type { SrtStatus } from "./srt-status.js";

export interface LinuxSandboxDoctorDeps {
  readFile: (path: string) => string | null;
  /** Runs a minimal bwrap sandbox; returns null on success or the error text. */
  probeBwrap: () => string | null;
  resolveBwrapPath: () => string;
}

const APPARMOR_USERNS_SYSCTL = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";

function readFileOrNull(path: string): string | null {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

function probeBwrap(): string | null {
  // Same namespaces SRT asks for, without network; exits immediately.
  const result = spawnSync("bwrap", ["--unshare-all", "--ro-bind", "/", "/", "true"], {
    encoding: "utf8",
    timeout: 5000,
  });
  if (result.error) return result.error.message;
  if (result.status === 0) return null;
  return (result.stderr || `bwrap exited with status ${result.status}`).trim();
}

function resolveBwrapPath(): string {
  const result = spawnSync("/bin/sh", ["-c", "command -v bwrap"], { encoding: "utf8" });
  const path = result.stdout.trim();
  if (!path) return "/usr/bin/bwrap";
  try {
    return realpathSync(path);
  } catch {
    return path;
  }
}

const DEFAULT_DEPS: LinuxSandboxDoctorDeps = {
  readFile: readFileOrNull,
  probeBwrap,
  resolveBwrapPath,
};

type PackageManager = "apt" | "dnf" | "pacman" | "zypper";

function detectPackageManager(osRelease: string | null): PackageManager | null {
  if (!osRelease) return null;
  const ids = [...osRelease.matchAll(/^(?:ID|ID_LIKE)=("?)([^"\n]*)\1$/gm)]
    .flatMap((match) => match[2]!.split(/\s+/))
    .filter(Boolean);
  if (ids.some((id) => ["debian", "ubuntu"].includes(id))) return "apt";
  if (ids.some((id) => ["fedora", "rhel", "centos"].includes(id))) return "dnf";
  if (ids.some((id) => ["arch"].includes(id))) return "pacman";
  if (ids.some((id) => ["suse", "opensuse"].includes(id) || id.startsWith("opensuse"))) return "zypper";
  return null;
}

const INSTALL_COMMANDS: Record<PackageManager, string> = {
  apt: "sudo apt install",
  dnf: "sudo dnf install",
  pacman: "sudo pacman -S",
  zypper: "sudo zypper install",
};

const PACKAGE_NAMES: Record<string, string> = { bwrap: "bubblewrap", socat: "socat", rg: "ripgrep" };

function appArmorProfileFix(bwrapPath: string): string[] {
  return [
    "Fix: bubblewrap is blocked by AppArmor's unprivileged user-namespace restriction (Ubuntu 24.04+).",
    "Allow it for bwrap only:",
    "",
    "  sudo tee /etc/apparmor.d/bwrap >/dev/null <<'EOF'",
    "  abi <abi/4.0>,",
    "  include <tunables/global>",
    `  profile bwrap ${bwrapPath} flags=(unconfined) {`,
    "    userns,",
    "    include if exists <local/bwrap>",
    "  }",
    "  EOF",
    "  sudo apparmor_parser -r /etc/apparmor.d/bwrap",
    "",
    "Then run /sandbox-status again.",
  ];
}

/**
 * Setup steps for a Linux SRT host, or [] when the sandbox works. Runs a real
 * bwrap probe, so call it from /sandbox-status, not on every command.
 */
export function diagnoseLinuxSandbox(
  status: SrtStatus,
  deps: LinuxSandboxDoctorDeps = DEFAULT_DEPS,
): string[] {
  if (status.platform !== "linux") return [];

  const missing = status.dependencyChecks.filter((dep) => !dep.available).map((dep) => dep.name);
  if (missing.length > 0) {
    const packages = missing.map((name) => PACKAGE_NAMES[name] ?? name).join(" ");
    const manager = detectPackageManager(deps.readFile("/etc/os-release"));
    return [manager
      ? `Fix: ${INSTALL_COMMANDS[manager]} ${packages}`
      : `Fix: install ${packages} with your package manager.`];
  }
  if (!status.available) return [];

  const probeError = deps.probeBwrap();
  if (probeError === null) return [];

  if (deps.readFile(APPARMOR_USERNS_SYSCTL)?.trim() === "1") {
    return [`bwrap test failed: ${probeError}`, ...appArmorProfileFix(deps.resolveBwrapPath())];
  }
  return [
    `bwrap test failed: ${probeError}`,
    "Fix: bubblewrap needs unprivileged user namespaces. Check that your kernel allows them (sysctl user.max_user_namespaces > 0).",
  ];
}
