import { afterEach, describe, expect, it } from "vitest";

import { DEFAULT_EXTENSION_CONFIG } from "./extension-config";
import { clearSessionLists, setSessionYoloAskPattern } from "./session-lists";
import { matchesYoloAskBashPattern } from "./yolo-mode";

const context = { toolName: "bash", command: "make deploy-prod" };

afterEach(() => clearSessionLists());

describe("session yolo ask patterns", () => {
  it("forces a yolo ask for a command that matches a session pattern", () => {
    expect(matchesYoloAskBashPattern(context, DEFAULT_EXTENSION_CONFIG)).toBe(false);

    setSessionYoloAskPattern("make deploy-*", true);

    expect(matchesYoloAskBashPattern(context, DEFAULT_EXTENSION_CONFIG)).toBe(true);
  });
});
