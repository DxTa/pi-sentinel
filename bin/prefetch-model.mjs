#!/usr/bin/env node
// Best-effort install-time prefetch of the auto-mode classifier. Never fails the install.
if (process.env.PI_SENTINEL_SKIP_MODEL_DOWNLOAD === "1" || process.env.CI) process.exit(0);
try {
  const { ensureModelAssets, resolveModelDir } = await import("../src/auto-mode-model.ts");
  await ensureModelAssets({ dir: resolveModelDir() });
} catch (error) {
  console.warn(`pi-sentinel: auto-mode model prefetch skipped (${error.message}); it downloads on first use.`);
}
