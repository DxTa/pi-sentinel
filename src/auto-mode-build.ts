import { createRequire } from "node:module";

import { DEFAULT_MODEL_PROFILE_ID, loadModelProfile } from "./auto-mode-profile.ts";

export const MODEL_PROFILE = loadModelProfile(DEFAULT_MODEL_PROFILE_ID);
export const MODEL_REVISION = MODEL_PROFILE.revision;
const { version: packageVersion } = createRequire(import.meta.url)("../package.json") as { version: string };
export const AUTO_MODE_BUILD_ID = packageVersion + ":" + MODEL_PROFILE.id + ":" + MODEL_REVISION;
