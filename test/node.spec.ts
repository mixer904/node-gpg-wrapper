import { EventEmitter, once } from "node:events";
import { PassThrough, Readable } from "node:stream";
import { describe, expect, it, vi } from "vitest";

import { GpgDecryptionError, GpgWrapper } from "../src";

class FakeChildProcess extends EventEmitter {
  public readonly stdin = new PassThrough();
  public readonly stdout = new PassThrough();
  public readonly stderr = new PassThrough();
}

describe("GpgWrapper decryptFile", () => {
  it("decrypts to memory and reports progress", async () => {
    const child = new FakeChildProcess();
    const spawn = vi.fn().mockReturnValue(child);
    const wrapper = new GpgWrapper({
      spawn,
      createReadStream: vi
        .fn()
        .mockReturnValue(Readable.from([Buffer.from("enc1"), Buffer.from("enc2")])),
      stat: vi.fn().mockResolvedValue({ size: 8 }),
    });

    const progressEvents: number[] = [];
    const donePromise = wrapper.decryptFile({
      inputPath: "input.gpg",
      passphrase: "test",
      onProgress: (progress) => {
        progressEvents.push(progress.percent);
      },
    });

    await once(child.stdin, "finish");
    child.stderr.write("[GNUPG:] BEGIN_DECRYPTION\n");
    child.stdout.write("hello ");
    child.stdout.write("world");
    child.stderr.write("[GNUPG:] DECRYPTION_OKAY\n");
    child.emit("close", 0);

    const result = await donePromise;

    expect(spawn).toHaveBeenCalledOnce();
    const [, args] = spawn.mock.calls[0] as [string, string[]];
    expect(args).toContain("--decrypt");
    expect(args).toContain("--passphrase");
    expect(result.plaintext?.toString("utf8")).toBe("hello world");
    expect(result.outputBytes).toBe(11);
    expect(result.statusLines).toContain("BEGIN_DECRYPTION");
    expect(result.statusLines).toContain("DECRYPTION_OKAY");
    expect(progressEvents.length).toBeGreaterThan(0);
    expect(progressEvents.at(-1)).toBe(100);
  });

  it("passes output path to gpg and omits plaintext buffer", async () => {
    const child = new FakeChildProcess();
    const spawn = vi.fn().mockReturnValue(child);
    const wrapper = new GpgWrapper({
      spawn,
      createReadStream: vi.fn().mockReturnValue(Readable.from([Buffer.from("enc")])),
      stat: vi.fn().mockResolvedValue({ size: 3 }),
    });

    const donePromise = wrapper.decryptFile({
      inputPath: "in.gpg",
      outputPath: "out.txt",
    });

    await once(child.stdin, "finish");
    child.emit("close", 0);
    const result = await donePromise;

    const [, args] = spawn.mock.calls[0] as [string, string[]];
    expect(args).toContain("--output");
    expect(args).toContain("out.txt");
    expect(result.plaintext).toBeUndefined();
    expect(result.outputPath).toBe("out.txt");
  });

  it("throws GpgDecryptionError when gpg exits non-zero", async () => {
    const child = new FakeChildProcess();
    const wrapper = new GpgWrapper({
      spawn: vi.fn().mockReturnValue(child),
      createReadStream: vi.fn().mockReturnValue(Readable.from([Buffer.from("enc")])),
      stat: vi.fn().mockResolvedValue({ size: 3 }),
    });

    const donePromise = wrapper.decryptFile({
      inputPath: "in.gpg",
    });

    await once(child.stdin, "finish");
    child.stderr.write("decryption failed");
    child.emit("close", 2);

    await expect(donePromise).rejects.toBeInstanceOf(GpgDecryptionError);
    await expect(donePromise).rejects.toMatchObject({
      exitCode: 2,
    });
  });

  it("supports homedir, custom gpg path, extra args, and signal", async () => {
    const child = new FakeChildProcess();
    const spawn = vi.fn().mockReturnValue(child);
    const wrapper = new GpgWrapper({
      spawn,
      createReadStream: vi.fn().mockReturnValue(Readable.from([Buffer.from("enc")])),
      stat: vi.fn().mockResolvedValue({ size: 3 }),
    });
    const controller = new AbortController();

    const donePromise = wrapper.decryptFile({
      inputPath: "in.gpg",
      gpgPath: "gpg2",
      homedir: "/tmp/gnupg",
      extraArgs: ["--quiet"],
      signal: controller.signal,
    });

    await once(child.stdin, "finish");
    child.emit("close", 0);
    await donePromise;

    const [command, args, spawnOptions] = spawn.mock.calls[0] as [
      string,
      string[],
      { signal?: AbortSignal },
    ];
    expect(command).toBe("gpg2");
    expect(args).toContain("--homedir");
    expect(args).toContain("/tmp/gnupg");
    expect(args).toContain("--quiet");
    expect(spawnOptions.signal).toBe(controller.signal);
  });

  it("rejects when child process emits an error", async () => {
    const child = new FakeChildProcess();
    const source = new PassThrough();
    source.end(Buffer.from("enc"));
    const wrapper = new GpgWrapper({
      spawn: vi.fn().mockReturnValue(child),
      createReadStream: vi.fn().mockReturnValue(source as unknown as Readable),
      stat: vi.fn().mockResolvedValue({ size: 3 }),
    });

    const sourceDestroy = vi.spyOn(source, "destroy");
    const donePromise = wrapper.decryptFile({ inputPath: "in.gpg" });
    await once(child.stdin, "finish");
    const expectedError = new Error("spawn failed");
    child.emit("error", expectedError);

    await expect(donePromise).rejects.toBe(expectedError);
    expect(sourceDestroy).toHaveBeenCalled();
  });

});
