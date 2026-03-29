# @mixer904/node-gpg-wrapper

A tiny TypeScript wrapper around the `gpg` CLI for decrypting files in Node.js, with progress reporting and typed results.

## What it does

- Decrypts an encrypted file by streaming it into `gpg`
- Returns plaintext in memory or writes directly to an output file
- Reports progress (`encryptedBytesRead`, `percent`, status events)
- Exposes structured decryption errors (`GpgDecryptionError`)
- Ships a browser entrypoint that throws a clear "not supported" error

## Install

```bash
npm i @mixer904/node-gpg-wrapper
```

Requirements:

- Node.js `>= 20`
- `gpg` installed and available in `PATH` (or pass a custom `gpgPath`)

## Usage (Node)

```ts
import { GpgWrapper } from "@mixer904/node-gpg-wrapper";

const gpg = new GpgWrapper();

const result = await gpg.decryptFile({
  inputPath: "./secret.txt.gpg",
  passphrase: process.env.GPG_PASSPHRASE,
  onProgress: (p) => {
    console.log(`${p.percent.toFixed(1)}%`, p.status ?? "");
  },
});

console.log(result.plaintext?.toString("utf8"));
console.log(result.durationMs);
```

### Decrypt to disk instead of memory

```ts
const result = await gpg.decryptFile({
  inputPath: "./secret.txt.gpg",
  outputPath: "./secret.txt",
});

console.log(result.outputPath); // ./secret.txt
console.log(result.plaintext); // undefined
```

## Browser entrypoint

```ts
import { decryptFile } from "@mixer904/node-gpg-wrapper/browser";

await decryptFile(); // throws BrowserNotSupportedError
```

Use the Node entrypoint for real decryption.

## API

### `class GpgWrapper`

- `decryptFile(options: DecryptFileOptions): Promise<DecryptResult>`

`GpgWrapper` also emits a `progress` event with `DecryptProgress`.

### `DecryptFileOptions`

- `inputPath: string` (required)
- `outputPath?: string`
- `passphrase?: string`
- `gpgPath?: string` (default: `gpg`)
- `homedir?: string`
- `extraArgs?: string[]`
- `onProgress?: (progress: DecryptProgress) => void`
- `signal?: AbortSignal`

### `DecryptProgress`

- `encryptedBytesRead: number`
- `encryptedTotalBytes: number`
- `outputBytes: number`
- `percent: number`
- `status?: string` (parsed from `[GNUPG:] ...` status lines)

### `DecryptResult`

- `plaintext?: Buffer` (only when `outputPath` is not set)
- `outputPath?: string`
- `encryptedBytesRead: number`
- `encryptedTotalBytes: number`
- `outputBytes: number`
- `durationMs: number`
- `statusLines: string[]`

### `GpgDecryptionError`

Thrown when `gpg` exits with non-zero code.

Properties:

- `exitCode: number | null`
- `stderr: string`
- `statusLines: string[]`

## Development

```bash
pnpm i
pnpm lint
pnpm test
pnpm build
```

Scripts:

- `pnpm dev` - watch build
- `pnpm size` - size-limit check for browser bundle

## License

MIT
