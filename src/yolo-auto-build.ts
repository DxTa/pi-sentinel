import { createRequire } from "node:module";

export const MODEL_REVISION = "77888f617584758f904faefd6f38d4cf926f6d5d";
const { version: packageVersion } = createRequire(import.meta.url)("../package.json") as { version: string };
export const YOLO_AUTO_BUILD_ID = packageVersion + ":" + MODEL_REVISION;
