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
        .mockReturnValue(
          Readable.from([Buffer.from("enc1"), Buffer.from("enc2")]),
        ),
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
      createReadStream: vi
        .fn()
        .mockReturnValue(Readable.from([Buffer.from("enc")])),
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
      createReadStream: vi
        .fn()
        .mockReturnValue(Readable.from([Buffer.from("enc")])),
      stat: vi.fn().mockResolvedValue({ size: 3 }),
    });

    const donePromise = wrapper.decryptFile({
      inputPath: "in.gpg",
    });

    await once(child.stdin, "finish");
    child.stderr.write("[GNUPG:] NO_SECKEY 1234567890ABCDEF\n");
    child.stderr.write("gpg: decryption failed: No secret key\n");
    child.emit("close", 2);

    await expect(donePromise).rejects.toBeInstanceOf(GpgDecryptionError);
    await expect(donePromise).rejects.toMatchObject({
      exitCode: 2,
    });
    await expect(donePromise).rejects.toMatchObject({
      message: expect.stringContaining(
        "No matching private key was found for this ciphertext",
      ),
    });
  });

  it("supports homedir, custom gpg path, extra args, and signal", async () => {
    const child = new FakeChildProcess();
    const spawn = vi.fn().mockReturnValue(child);
    const wrapper = new GpgWrapper({
      spawn,
      createReadStream: vi
        .fn()
        .mockReturnValue(Readable.from([Buffer.from("enc")])),
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

  it("imports a private key from inline content before decrypting", async () => {
    const importChild = new FakeChildProcess();
    const decryptChild = new FakeChildProcess();
    const spawn = vi
      .fn()
      .mockReturnValueOnce(importChild)
      .mockReturnValueOnce(decryptChild);
    const wrapper = new GpgWrapper({
      spawn,
      createReadStream: vi
        .fn()
        .mockReturnValue(Readable.from([Buffer.from("enc")])),
      stat: vi.fn().mockResolvedValue({ size: 3 }),
    });
    let importedKey = "";
    importChild.stdin.on("data", (chunk: Buffer) => {
      importedKey += chunk.toString("utf8");
    });

    const donePromise = wrapper.decryptFile({
      inputPath: "in.gpg",
      homedir: "/tmp/gnupg",
      privateKey: "-----BEGIN PGP PRIVATE KEY BLOCK-----\nabc\n-----END-----",
    });

    await once(importChild.stdin, "finish");
    importChild.emit("close", 0);
    await once(decryptChild.stdin, "finish");
    decryptChild.emit("close", 0);
    await donePromise;

    expect(spawn).toHaveBeenCalledTimes(2);
    const [, importArgs] = spawn.mock.calls[0] as [string, string[]];
    expect(importArgs).toContain("--import");
    expect(importArgs).toContain("--homedir");
    expect(importArgs).toContain("/tmp/gnupg");
    expect(importedKey).toContain("BEGIN PGP PRIVATE KEY BLOCK");

    const [, decryptArgs] = spawn.mock.calls[1] as [string, string[]];
    expect(decryptArgs).toContain("--decrypt");
    expect(decryptArgs).toContain("--homedir");
    expect(decryptArgs).toContain("/tmp/gnupg");
  });

  it("imports a private key from a file path before decrypting", async () => {
    const importChild = new FakeChildProcess();
    const decryptChild = new FakeChildProcess();
    const spawn = vi
      .fn()
      .mockReturnValueOnce(importChild)
      .mockReturnValueOnce(decryptChild);
    const wrapper = new GpgWrapper({
      spawn,
      createReadStream: vi
        .fn()
        .mockReturnValue(Readable.from([Buffer.from("enc")])),
      stat: vi.fn().mockResolvedValue({ size: 3 }),
    });

    const donePromise = wrapper.decryptFile({
      inputPath: "in.gpg",
      homedir: "/tmp/gnupg",
      privateKey: "/keys/private.asc",
    });

    await once(importChild.stdin, "finish");
    importChild.emit("close", 0);
    await once(decryptChild.stdin, "finish");
    decryptChild.emit("close", 0);
    await donePromise;

    const [, importArgs] = spawn.mock.calls[0] as [string, string[]];
    expect(importArgs).toContain("--import");
    expect(importArgs).toContain("/keys/private.asc");
  });

  it("imports key content when key has line breaks but no armor header", async () => {
    const importChild = new FakeChildProcess();
    const decryptChild = new FakeChildProcess();
    const spawn = vi
      .fn()
      .mockReturnValueOnce(importChild)
      .mockReturnValueOnce(decryptChild);
    const wrapper = new GpgWrapper({
      spawn,
      createReadStream: vi
        .fn()
        .mockReturnValue(Readable.from([Buffer.from("enc")])),
      stat: vi.fn().mockResolvedValue({ size: 3 }),
    });
    let importedKey = "";
    importChild.stdin.on("data", (chunk: Buffer) => {
      importedKey += chunk.toString("utf8");
    });

    const donePromise = wrapper.decryptFile({
      inputPath: "in.gpg",
      homedir: "/tmp/gnupg",
      privateKey: "line1\nline2",
    });

    await once(importChild.stdin, "finish");
    importChild.emit("close", 0);
    await once(decryptChild.stdin, "finish");
    decryptChild.emit("close", 0);
    await donePromise;

    expect(importedKey).toBe("line1\nline2");
  });

  it("throws GpgDecryptionError when private key import exits non-zero", async () => {
    const importChild = new FakeChildProcess();
    const spawn = vi.fn().mockReturnValue(importChild);
    const wrapper = new GpgWrapper({
      spawn,
      createReadStream: vi.fn(),
      stat: vi.fn(),
    });

    const donePromise = wrapper.decryptFile({
      inputPath: "in.gpg",
      homedir: "/tmp/gnupg",
      privateKey: "/keys/private.asc",
    });

    await once(importChild.stdin, "finish");
    importChild.stderr.write("gpg: key import failed: bad passphrase\n");
    importChild.emit("close", 2);

    await expect(donePromise).rejects.toBeInstanceOf(GpgDecryptionError);
    await expect(donePromise).rejects.toMatchObject({
      exitCode: 2,
    });
    await expect(donePromise).rejects.toMatchObject({
      message: expect.stringContaining("The provided passphrase is incorrect"),
    });
    expect(spawn).toHaveBeenCalledTimes(1);
  });

  it("rejects when private key import process emits an error", async () => {
    const importChild = new FakeChildProcess();
    const wrapper = new GpgWrapper({
      spawn: vi.fn().mockReturnValue(importChild),
      createReadStream: vi.fn(),
      stat: vi.fn(),
    });

    const donePromise = wrapper.decryptFile({
      inputPath: "in.gpg",
      homedir: "/tmp/gnupg",
      privateKey: "/keys/private.asc",
    });

    await once(importChild.stdin, "finish");
    const expectedError = new Error("import spawn failed");
    importChild.emit("error", expectedError);

    await expect(donePromise).rejects.toBe(expectedError);
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

  it("includes a missing passphrase hint in the error message", async () => {
    const child = new FakeChildProcess();
    const wrapper = new GpgWrapper({
      spawn: vi.fn().mockReturnValue(child),
      createReadStream: vi
        .fn()
        .mockReturnValue(Readable.from([Buffer.from("enc")])),
      stat: vi.fn().mockResolvedValue({ size: 3 }),
    });

    const donePromise = wrapper.decryptFile({ inputPath: "in.gpg" });

    await once(child.stdin, "finish");
    child.stderr.write("[GNUPG:] NEED_PASSPHRASE\n");
    child.stderr.write("gpg: Inappropriate ioctl for device\n");
    child.emit("close", 2);

    await expect(donePromise).rejects.toMatchObject({
      message: expect.stringContaining(
        "A passphrase is required but none was provided",
      ),
    });
  });

  it("includes an invalid input hint in the error message", async () => {
    const child = new FakeChildProcess();
    const wrapper = new GpgWrapper({
      spawn: vi.fn().mockReturnValue(child),
      createReadStream: vi
        .fn()
        .mockReturnValue(Readable.from([Buffer.from("enc")])),
      stat: vi.fn().mockResolvedValue({ size: 3 }),
    });

    const donePromise = wrapper.decryptFile({ inputPath: "in.gpg" });

    await once(child.stdin, "finish");
    child.stderr.write("[GNUPG:] NODATA 1\n");
    child.stderr.write("gpg: no valid OpenPGP data found.\n");
    child.emit("close", 2);

    await expect(donePromise).rejects.toMatchObject({
      message: expect.stringContaining("Input is not valid OpenPGP encrypted data"),
    });
  });

  it("includes stderr details in generic gpg errors", async () => {
    const child = new FakeChildProcess();
    const wrapper = new GpgWrapper({
      spawn: vi.fn().mockReturnValue(child),
      createReadStream: vi
        .fn()
        .mockReturnValue(Readable.from([Buffer.from("enc")])),
      stat: vi.fn().mockResolvedValue({ size: 3 }),
    });

    const donePromise = wrapper.decryptFile({ inputPath: "in.gpg" });

    await once(child.stdin, "finish");
    child.stderr.write("gpg: unexpected failure detail\n");
    child.emit("close", 2);

    await expect(donePromise).rejects.toMatchObject({
      message: expect.stringContaining("stderr: gpg: unexpected failure detail"),
    });
  });

  it("includes no-secret-key hint when only stderr contains the cause", async () => {
    const child = new FakeChildProcess();
    const wrapper = new GpgWrapper({
      spawn: vi.fn().mockReturnValue(child),
      createReadStream: vi
        .fn()
        .mockReturnValue(Readable.from([Buffer.from("enc")])),
      stat: vi.fn().mockResolvedValue({ size: 3 }),
    });

    const donePromise = wrapper.decryptFile({ inputPath: "in.gpg" });

    await once(child.stdin, "finish");
    child.stderr.write("gpg: decryption failed: No secret key\n");
    child.emit("close", 2);

    await expect(donePromise).rejects.toMatchObject({
      message: expect.stringContaining(
        "No secret key is available to decrypt this message",
      ),
    });
  });

  it("keeps error message usable when gpg exits without code and stderr", async () => {
    const child = new FakeChildProcess();
    const wrapper = new GpgWrapper({
      spawn: vi.fn().mockReturnValue(child),
      createReadStream: vi
        .fn()
        .mockReturnValue(Readable.from([Buffer.from("enc")])),
      stat: vi.fn().mockResolvedValue({ size: 3 }),
    });

    const donePromise = wrapper.decryptFile({ inputPath: "in.gpg" });

    await once(child.stdin, "finish");
    child.emit("close", null);

    await expect(donePromise).rejects.toMatchObject({
      message: expect.stringContaining("exit code null"),
    });
  });
});
