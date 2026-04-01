import { spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import { createReadStream } from "node:fs";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Readable, Writable } from "node:stream";

export interface DecryptProgress {
  encryptedBytesRead: number;
  encryptedTotalBytes: number;
  outputBytes: number;
  percent: number;
  status?: string;
}

export interface DecryptFileOptions {
  inputPath: string;
  outputPath?: string;
  passphrase?: string;
  privateKey?: string;
  gpgPath?: string;
  homedir?: string;
  extraArgs?: string[];
  onProgress?: (progress: DecryptProgress) => void;
  signal?: AbortSignal;
}

export interface DecryptResult {
  plaintext?: Buffer;
  outputPath?: string;
  encryptedBytesRead: number;
  encryptedTotalBytes: number;
  outputBytes: number;
  durationMs: number;
  statusLines: string[];
}

export class GpgDecryptionError extends Error {
  public readonly exitCode: number | null;
  public readonly stderr: string;
  public readonly statusLines: string[];

  public constructor(
    message: string,
    exitCode: number | null,
    stderr: string,
    statusLines: string[],
  ) {
    super(message);
    this.name = "GpgDecryptionError";
    this.exitCode = exitCode;
    this.stderr = stderr;
    this.statusLines = statusLines;
  }
}

type GpgOperation = "decrypt" | "private key import";

interface SpawnedProcess extends EventEmitter {
  stdin: Writable;
  stdout: Readable;
  stderr: Readable;
}

type SpawnFn = (
  command: string,
  args: string[],
  options: { stdio: ["pipe", "pipe", "pipe"]; signal?: AbortSignal },
) => SpawnedProcess;

interface RuntimeDeps {
  spawn: SpawnFn;
  createReadStream: typeof createReadStream;
  stat: typeof stat;
}

const defaultRuntime: RuntimeDeps = {
  spawn: (command, args, options) => spawn(command, args, options),
  createReadStream,
  stat,
};

export class GpgWrapper extends EventEmitter {
  private readonly runtime: RuntimeDeps;

  public constructor(runtime: RuntimeDeps = defaultRuntime) {
    super();
    this.runtime = runtime;
  }

  public async decryptFile(
    options: DecryptFileOptions,
  ): Promise<DecryptResult> {
    const startedAt = Date.now();
    const gpgPath = options.gpgPath ?? "gpg";
    const tempHomedir =
      options.privateKey && !options.homedir
        ? await mkdtemp(join(tmpdir(), "node-gpg-wrapper-"))
        : undefined;
    const homedir = options.homedir ?? tempHomedir;

    try {
      if (options.privateKey) {
        await this.importPrivateKey({
          gpgPath,
          homedir,
          privateKey: options.privateKey,
          signal: options.signal,
        });
      }

      const encryptedTotalBytes = (await this.runtime.stat(options.inputPath))
        .size;
      const args = this.buildDecryptArgs(options, homedir);
      const child = this.runtime.spawn(gpgPath, args, {
        stdio: ["pipe", "pipe", "pipe"],
        signal: options.signal,
      });
      const source = this.runtime.createReadStream(options.inputPath);

      let encryptedBytesRead = 0;
      let outputBytes = 0;
      let stderr = "";
      const statusLines: string[] = [];
      const plaintextChunks: Buffer[] = [];
      let stderrBuffer = "";

      const emitProgress = (status?: string) => {
        const percent =
          encryptedTotalBytes === 0
            ? 100
            : Math.min((encryptedBytesRead / encryptedTotalBytes) * 100, 100);
        const progress: DecryptProgress = {
          encryptedBytesRead,
          encryptedTotalBytes,
          outputBytes,
          percent,
          status,
        };
        options.onProgress?.(progress);
        this.emit("progress", progress);
      };

      source.on("data", (chunk: string | Buffer<ArrayBufferLike>) => {
        encryptedBytesRead += chunk.length;
        emitProgress();
      });

      child.stdout.on("data", (chunk: Buffer) => {
        outputBytes += chunk.length;
        if (!options.outputPath) {
          plaintextChunks.push(Buffer.from(chunk));
        }
      });

      child.stderr.on("data", (chunk: Buffer) => {
        const text = chunk.toString("utf8");
        stderr += text;
        stderrBuffer += text;
        const lines = stderrBuffer.split(/\r?\n/u);
        stderrBuffer = lines.pop() ?? "";
        for (const line of lines) {
          const status = parseStatusLine(line);
          if (status) {
            statusLines.push(status);
            emitProgress(status);
          }
        }
      });

      const done = new Promise<DecryptResult>((resolve, reject) => {
        child.once("error", (error: Error) => {
          source.destroy();
          reject(error);
        });

        child.once("close", (exitCode: number | null) => {
          if (stderrBuffer.length > 0) {
            const status = parseStatusLine(stderrBuffer);
            if (status) {
              statusLines.push(status);
            }
          }
          emitProgress("COMPLETE");
          if (exitCode !== 0) {
            reject(
              new GpgDecryptionError(
                buildGpgErrorMessage({
                  operation: "decrypt",
                  exitCode,
                  stderr,
                  statusLines,
                }),
                exitCode,
                stderr,
                statusLines,
              ),
            );
            return;
          }
          const durationMs = Date.now() - startedAt;
          resolve({
            plaintext: options.outputPath
              ? undefined
              : Buffer.concat(plaintextChunks),
            outputPath: options.outputPath,
            encryptedBytesRead,
            encryptedTotalBytes,
            outputBytes,
            durationMs,
            statusLines,
          });
        });
      });

      source.once("error", (error) => {
        child.stdin.destroy(error);
      });

      source.pipe(child.stdin);
      return done;
    } finally {
      if (tempHomedir) {
        await rm(tempHomedir, { recursive: true, force: true });
      }
    }
  }

  private async importPrivateKey(options: {
    gpgPath: string;
    homedir?: string;
    privateKey: string;
    signal?: AbortSignal;
  }): Promise<void> {
    const args: string[] = ["--batch", "--yes", "--status-fd", "2"];
    if (options.homedir) {
      args.push("--homedir", options.homedir);
    }
    args.push("--import");
    const privateKeyInput = parsePrivateKeyInput(options.privateKey);
    if (privateKeyInput.type === "path") {
      args.push(privateKeyInput.value);
    }
    const child = this.runtime.spawn(options.gpgPath, args, {
      stdio: ["pipe", "pipe", "pipe"],
      signal: options.signal,
    });
    child.stdout.resume();

    let stderr = "";
    let stderrBuffer = "";
    const statusLines: string[] = [];

    child.stderr.on("data", (chunk: Buffer) => {
      const text = chunk.toString("utf8");
      stderr += text;
      stderrBuffer += text;
      const lines = stderrBuffer.split(/\r?\n/u);
      stderrBuffer = lines.pop() ?? "";
      for (const line of lines) {
        const status = parseStatusLine(line);
        if (status) {
          statusLines.push(status);
        }
      }
    });

    if (privateKeyInput.type === "content") {
      child.stdin.end(privateKeyInput.value);
    } else {
      child.stdin.end();
    }

    await new Promise<void>((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (exitCode: number | null) => {
        if (stderrBuffer.length > 0) {
          const status = parseStatusLine(stderrBuffer);
          if (status) {
            statusLines.push(status);
          }
        }
        if (exitCode !== 0) {
          reject(
            new GpgDecryptionError(
              buildGpgErrorMessage({
                operation: "private key import",
                exitCode,
                stderr,
                statusLines,
              }),
              exitCode,
              stderr,
              statusLines,
            ),
          );
          return;
        }
        resolve();
      });
    });
  }

  private buildDecryptArgs(
    options: DecryptFileOptions,
    homedir?: string,
  ): string[] {
    const args: string[] = ["--batch", "--yes", "--status-fd", "2"];
    if (homedir) {
      args.push("--homedir", homedir);
    }
    if (options.passphrase) {
      args.push(
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        options.passphrase,
      );
    }
    if (options.extraArgs?.length) {
      args.push(...options.extraArgs);
    }
    if (options.outputPath) {
      args.push("--output", options.outputPath);
    }
    args.push("--decrypt", "-");
    return args;
  }
}

function parseStatusLine(line: string): string | undefined {
  const prefix = "[GNUPG:]";
  if (!line.startsWith(prefix)) {
    return undefined;
  }
  return line.slice(prefix.length).trim();
}

function parsePrivateKeyInput(
  privateKey: string,
): { type: "content"; value: string } | { type: "path"; value: string } {
  if (privateKey.includes("BEGIN PGP PRIVATE KEY BLOCK")) {
    return { type: "content", value: privateKey };
  }
  if (privateKey.includes("\n") || privateKey.includes("\r")) {
    return { type: "content", value: privateKey };
  }
  return { type: "path", value: privateKey };
}

function buildGpgErrorMessage(params: {
  operation: GpgOperation;
  exitCode: number | null;
  stderr: string;
  statusLines: string[];
}): string {
  const details = diagnoseGpgFailure(params.stderr, params.statusLines);
  const parts = [
    `gpg ${params.operation} failed (exit code ${params.exitCode ?? "null"})`,
  ];
  if (details.reason) {
    parts.push(details.reason);
  }
  if (details.hint) {
    parts.push(`Hint: ${details.hint}`);
  }
  if (details.stderrLine) {
    parts.push(`stderr: ${details.stderrLine}`);
  }
  return parts.join(". ");
}

function diagnoseGpgFailure(
  stderr: string,
  statusLines: string[],
): {
  reason?: string;
  hint?: string;
  stderrLine?: string;
} {
  const normalizedStderr = stderr.toLowerCase();
  const hasStatus = (prefix: string) =>
    statusLines.some((line) => line.startsWith(prefix));
  const stderrLine = getLastNonEmptyLine(stderr);

  if (hasStatus("NO_SECKEY")) {
    return {
      reason: "No matching private key was found for this ciphertext",
      hint: "Provide the correct private key (and homedir) before decrypting",
      stderrLine,
    };
  }

  if (
    hasStatus("BAD_PASSPHRASE") ||
    normalizedStderr.includes("bad passphrase") ||
    normalizedStderr.includes("invalid passphrase")
  ) {
    return {
      reason: "The provided passphrase is incorrect",
      hint: "Use the passphrase for the encrypted message or the private key",
      stderrLine,
    };
  }

  if (
    hasStatus("MISSING_PASSPHRASE") ||
    hasStatus("NEED_PASSPHRASE") ||
    normalizedStderr.includes("no passphrase") ||
    normalizedStderr.includes("inappropriate ioctl for device")
  ) {
    return {
      reason: "A passphrase is required but none was provided",
      hint: "Pass `passphrase` and keep `--pinentry-mode loopback` enabled",
      stderrLine,
    };
  }

  if (
    hasStatus("NODATA") ||
    normalizedStderr.includes("no valid openpgp data") ||
    normalizedStderr.includes("packet(62)")
  ) {
    return {
      reason: "Input is not valid OpenPGP encrypted data",
      hint: "Verify that `inputPath` points to the encrypted `.gpg` file",
      stderrLine,
    };
  }

  if (normalizedStderr.includes("no secret key")) {
    return {
      reason: "No secret key is available to decrypt this message",
      hint: "Import the right private key or use the correct gpg homedir",
      stderrLine,
    };
  }

  return { stderrLine };
}

function getLastNonEmptyLine(input: string): string | undefined {
  const lines = input
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  return lines.at(-1);
}
