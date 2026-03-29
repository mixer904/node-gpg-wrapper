import { EventEmitter, once } from "node:events";
import { PassThrough, Readable } from "node:stream";
import { describe, expect, it, vi } from "vitest";

import { GpgWrapper } from "../src";

class FakeChildProcess extends EventEmitter {
  public readonly stdin = new PassThrough();
  public readonly stdout = new PassThrough();
  public readonly stderr = new PassThrough();
}

describe("GpgWrapper events", () => {
  it("emits progress events", async () => {
    const child = new FakeChildProcess();
    const wrapper = new GpgWrapper({
      spawn: vi.fn().mockReturnValue(child),
      createReadStream: vi
        .fn()
        .mockReturnValue(Readable.from([Buffer.from("a"), Buffer.from("b")])),
      stat: vi.fn().mockResolvedValue({ size: 2 }),
    });

    const eventStatuses: string[] = [];
    wrapper.on("progress", (event) => {
      if (event.status) {
        eventStatuses.push(event.status);
      }
    });

    const donePromise = wrapper.decryptFile({ inputPath: "a.gpg" });
    await once(child.stdin, "finish");
    child.stderr.write("[GNUPG:] BEGIN_DECRYPTION\n");
    child.emit("close", 0);

    const result = await donePromise;
    expect(result.encryptedBytesRead).toBe(2);
    expect(eventStatuses).toContain("BEGIN_DECRYPTION");
    expect(eventStatuses).toContain("COMPLETE");
  });
});
