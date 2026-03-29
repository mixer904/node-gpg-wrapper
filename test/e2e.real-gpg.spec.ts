import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { GpgWrapper } from "../src";

const gpgAvailable = isGpgAvailable();
const describeWithGpg = gpgAvailable ? describe : describe.skip;

describeWithGpg("GpgWrapper e2e (real gpg)", () => {
  let tempDir: string | undefined;

  afterEach(async () => {
    if (tempDir) {
      await rm(tempDir, { recursive: true, force: true });
      tempDir = undefined;
    }
  });

  it("decrypts symmetric encrypted data to memory", async () => {
    tempDir = await mkdtemp(join(tmpdir(), "node-gpg-wrapper-e2e-"));
    const passphrase = "correct horse battery staple";
    const plaintext = "Hello from real gpg";
    const inputPath = join(tempDir, "plaintext.txt");
    const encryptedPath = join(tempDir, "plaintext.txt.gpg");

    await writeFile(inputPath, plaintext, "utf8");
    runGpg([
      "--batch",
      "--yes",
      "--pinentry-mode",
      "loopback",
      "--passphrase",
      passphrase,
      "--symmetric",
      "--output",
      encryptedPath,
      inputPath,
    ]);

    const statusEvents: string[] = [];
    const wrapper = new GpgWrapper();
    const result = await wrapper.decryptFile({
      inputPath: encryptedPath,
      passphrase,
      onProgress: (progress) => {
        if (progress.status) {
          statusEvents.push(progress.status);
        }
      },
    });

    expect(result.plaintext?.toString("utf8")).toBe(plaintext);
    expect(result.encryptedBytesRead).toBeGreaterThan(0);
    expect(result.encryptedTotalBytes).toBeGreaterThan(0);
    expect(result.statusLines).toContain("DECRYPTION_OKAY");
    expect(statusEvents).toContain("COMPLETE");
  }, 20_000);

  it("decrypts to output file when outputPath is set", async () => {
    tempDir = await mkdtemp(join(tmpdir(), "node-gpg-wrapper-e2e-"));
    const passphrase = "test passphrase";
    const plaintext = "write to output file";
    const inputPath = join(tempDir, "plaintext.txt");
    const encryptedPath = join(tempDir, "plaintext.txt.gpg");
    const outputPath = join(tempDir, "decrypted.txt");

    await writeFile(inputPath, plaintext, "utf8");
    runGpg([
      "--batch",
      "--yes",
      "--pinentry-mode",
      "loopback",
      "--passphrase",
      passphrase,
      "--symmetric",
      "--output",
      encryptedPath,
      inputPath,
    ]);

    const wrapper = new GpgWrapper();
    const result = await wrapper.decryptFile({
      inputPath: encryptedPath,
      outputPath,
      passphrase,
    });
    const fileContents = await readFile(outputPath, "utf8");

    expect(result.plaintext).toBeUndefined();
    expect(result.outputPath).toBe(outputPath);
    expect(result.outputBytes).toBe(0);
    expect(fileContents).toBe(plaintext);
  }, 20_000);
});

function isGpgAvailable(): boolean {
  const result = spawnSync("gpg", ["--version"], { stdio: "ignore" });
  return result.status === 0;
}

function runGpg(args: string[]): void {
  const result = spawnSync("gpg", args, { encoding: "utf8" });
  if (result.status === 0) {
    return;
  }
  throw new Error(
    [
      `Failed to execute gpg ${args.join(" ")}`,
      `exit code: ${result.status ?? "null"}`,
      `stderr: ${result.stderr?.trim() ?? ""}`,
    ].join("\n"),
  );
}
