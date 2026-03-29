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

  it("creates and removes a temp homedir when privateKey is provided without homedir", async () => {
    const importChild = new FakeChildProcess();
    const decryptChild = new FakeChildProcess();
    const mockSpawn = vi
      .fn()
      .mockReturnValueOnce(importChild)
      .mockReturnValueOnce(decryptChild);
    const mockCreateReadStream = vi
      .fn()
      .mockReturnValue(Readable.from([Buffer.from("enc")]));
    const mockStat = vi.fn().mockResolvedValue({ size: 3 });
    const mockMkdtemp = vi.fn().mockResolvedValue("/tmp/node-gpg-wrapper-123");
    const mockRm = vi.fn().mockResolvedValue(undefined);

    vi.doMock("node:child_process", () => ({ spawn: mockSpawn }));
    vi.doMock("node:fs", () => ({ createReadStream: mockCreateReadStream }));
    vi.doMock("node:fs/promises", () => ({
      stat: mockStat,
      mkdtemp: mockMkdtemp,
      rm: mockRm,
    }));

    const { GpgWrapper } = await import("../src/gpg-wrapper");
    const wrapper = new GpgWrapper();
    const donePromise = wrapper.decryptFile({
      inputPath: "in.gpg",
      privateKey: "/keys/private.asc",
    });

    await once(importChild.stdin, "finish");
    importChild.emit("close", 0);
    await once(decryptChild.stdin, "finish");
    decryptChild.emit("close", 0);
    await donePromise;

    expect(mockMkdtemp).toHaveBeenCalledOnce();
    expect(mockRm).toHaveBeenCalledWith("/tmp/node-gpg-wrapper-123", {
      recursive: true,
      force: true,
    });
    expect(mockSpawn).toHaveBeenCalledTimes(2);
    const [, importArgs] = mockSpawn.mock.calls[0] as [string, string[]];
    expect(importArgs).toContain("--homedir");
    expect(importArgs).toContain("/tmp/node-gpg-wrapper-123");
  });
});
