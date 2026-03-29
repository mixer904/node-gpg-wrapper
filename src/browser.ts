export class BrowserNotSupportedError extends Error {
  public constructor() {
    super(
      "GPG decryption is not supported in browser builds. Use the Node entrypoint.",
    );
    this.name = "BrowserNotSupportedError";
  }
}

export async function decryptFile(): Promise<never> {
  throw new BrowserNotSupportedError();
}
