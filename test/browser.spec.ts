import { describe, expect, it } from "vitest";

import { BrowserNotSupportedError, decryptFile } from "../src/browser";

describe("browser adapter", () => {
  it("throws not-supported for decryption", async () => {
    await expect(decryptFile()).rejects.toBeInstanceOf(
      BrowserNotSupportedError,
    );
  });
});
