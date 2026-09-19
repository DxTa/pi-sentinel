import type {
  ExtensionCommandContext,
  ExtensionContext,
} from "@earendil-works/pi-coding-agent";

import {
  EXTENSION_ID,
  type PermissionSystemExtensionConfig,
} from "./extension-config";
import { isYoloModeEnabled } from "./yolo-mode";

export const PERMISSION_SYSTEM_STATUS_KEY = EXTENSION_ID;
export const PERMISSION_SYSTEM_YOLO_STATUS_VALUE = "yolo";
export const PERMISSION_SYSTEM_YOLO_AUTO_STATUS_VALUE = "yolo-auto";
export const PERMISSION_SYSTEM_YOLO_BOTH_STATUS_VALUE = "yolo+yolo-auto";

type PermissionStatusContext =
  | Pick<ExtensionContext, "hasUI" | "ui">
  | Pick<ExtensionCommandContext, "ui">;

export function getPermissionSystemStatus(
  config: PermissionSystemExtensionConfig,
): string | undefined {
  if (isYoloModeEnabled(config) && config.yoloAutoMode) {
    return PERMISSION_SYSTEM_YOLO_BOTH_STATUS_VALUE;
  }
  if (isYoloModeEnabled(config)) {
    return PERMISSION_SYSTEM_YOLO_STATUS_VALUE;
  }
  return config.yoloAutoMode
    ? PERMISSION_SYSTEM_YOLO_AUTO_STATUS_VALUE
    : undefined;
}

export function syncPermissionSystemStatus(
  ctx: PermissionStatusContext,
  config: PermissionSystemExtensionConfig,
): void {
  ctx.ui.setStatus(
    PERMISSION_SYSTEM_STATUS_KEY,
    getPermissionSystemStatus(config),
  );
}
