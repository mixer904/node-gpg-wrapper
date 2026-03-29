import { EventEmitter, once } from "node:events";
import { PassThrough, Readable } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";

class FakeChildProcess extends EventEmitter {
  public readonly stdin = new PassThrough();
  public readonly stdout = new PassThrough();
  public readonly stderr = new PassThrough();
}

describe("GpgWrapper default runtime", () => {
  afterEach(() => {
    vi.resetModules();
    vi.doUnmock("node:child_process");
    vi.doUnmock("node:fs");
    vi.doUnmock("node:fs/promises");
  });

  it("uses built-in spawn/fs dependencies when no runtime is provided", async () => {
    const child = new FakeChildProcess();
    const mockSpawn = vi.fn().mockReturnValue(child);
    const mockCreateReadStream = vi
      .fn()
      .mockReturnValue(Readable.from([Buffer.from("enc")]));
    const mockStat = vi.fn().mockResolvedValue({ size: 3 });

    vi.doMock("node:child_process", () => ({ spawn: mockSpawn }));
    vi.doMock("node:fs", () => ({ createReadStream: mockCreateReadStream }));
    vi.doMock("node:fs/promises", () => ({ stat: mockStat }));

    const { GpgWrapper } = await import("../src/gpg-wrapper");
    const wrapper = new GpgWrapper();
    const donePromise = wrapper.decryptFile({ inputPath: "in.gpg" });

    await once(child.stdin, "finish");
    child.emit("close", 0);
    await donePromise;

    expect(mockSpawn).toHaveBeenCalledOnce();
    expect(mockCreateReadStream).toHaveBeenCalledWith("in.gpg");
    expect(mockStat).toHaveBeenCalledWith("in.gpg");
  });
});
