import fs from "node:fs";
import path from "node:path";
import {
  decryptCredentialData,
  encryptCredentialData,
  isEncryptedPayload,
} from "./credential-encryption.js";

export function loadJsonFile(pathname: string): unknown {
  try {
    if (!fs.existsSync(pathname)) {
      return undefined;
    }
    const raw = fs.readFileSync(pathname, "utf8");
    return JSON.parse(raw) as unknown;
  } catch {
    return undefined;
  }
}

export function saveJsonFile(pathname: string, data: unknown) {
  const dir = path.dirname(pathname);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  fs.writeFileSync(pathname, `${JSON.stringify(data, null, 2)}\n`, "utf8");
  fs.chmodSync(pathname, 0o600);
}

/**
 * Load a JSON file that may be stored encrypted (AES-256-GCM).
 * Transparently handles both plaintext (legacy) and encrypted formats.
 */
export function loadEncryptedJsonFile(pathname: string): unknown {
  try {
    if (!fs.existsSync(pathname)) {
      return undefined;
    }
    const raw = fs.readFileSync(pathname, "utf8");
    const parsed = JSON.parse(raw) as unknown;
    if (isEncryptedPayload(parsed)) {
      const decrypted = decryptCredentialData(parsed);
      return JSON.parse(decrypted) as unknown;
    }
    // Legacy plaintext file — return as-is (will be encrypted on next save)
    return parsed;
  } catch {
    return undefined;
  }
}

/**
 * Save a JSON file encrypted at rest using AES-256-GCM with a device-derived key.
 */
export function saveEncryptedJsonFile(pathname: string, data: unknown) {
  const dir = path.dirname(pathname);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  const plaintext = JSON.stringify(data, null, 2);
  const encrypted = encryptCredentialData(plaintext);
  fs.writeFileSync(pathname, `${JSON.stringify(encrypted)}\n`, "utf8");
  fs.chmodSync(pathname, 0o600);
}
