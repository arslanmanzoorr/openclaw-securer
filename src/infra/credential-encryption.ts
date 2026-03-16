import crypto from "node:crypto";
import { loadOrCreateDeviceIdentity } from "./device-identity.js";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const HKDF_SALT = Buffer.from("openclaw-credential-store-v1", "utf8");
const HKDF_INFO = Buffer.from("auth-profiles-encryption", "utf8");

let cachedEncryptionKey: Buffer | null = null;

/**
 * Derive a 256-bit AES key from the device identity private key using HKDF.
 * The device identity is unique per installation and stored with 0o600 perms,
 * making it a suitable key source for encrypting credentials at rest.
 */
function deriveEncryptionKey(): Buffer {
  if (cachedEncryptionKey) {
    return cachedEncryptionKey;
  }
  const identity = loadOrCreateDeviceIdentity();
  const keyMaterial = Buffer.from(identity.privateKeyPem, "utf8");
  cachedEncryptionKey = Buffer.from(
    crypto.hkdfSync("sha256", keyMaterial, HKDF_SALT, HKDF_INFO, 32),
  );
  return cachedEncryptionKey;
}

export type EncryptedPayload = {
  v: 1;
  alg: "aes-256-gcm";
  iv: string;
  tag: string;
  ct: string;
};

/**
 * Encrypt a UTF-8 string using AES-256-GCM with a device-derived key.
 * Returns a structured payload containing IV, auth tag, and ciphertext (all base64).
 */
export function encryptCredentialData(plaintext: string): EncryptedPayload {
  const key = deriveEncryptionKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return {
    v: 1,
    alg: ALGORITHM,
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    ct: encrypted.toString("base64"),
  };
}

/**
 * Decrypt an AES-256-GCM encrypted payload back to a UTF-8 string.
 * Throws on tampered data or wrong key.
 */
export function decryptCredentialData(payload: EncryptedPayload): string {
  const key = deriveEncryptionKey();
  const iv = Buffer.from(payload.iv, "base64");
  const tag = Buffer.from(payload.tag, "base64");
  const ct = Buffer.from(payload.ct, "base64");
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString(
    "utf8",
  );
}

/**
 * Check if an unknown parsed JSON value looks like an encrypted payload.
 */
export function isEncryptedPayload(value: unknown): value is EncryptedPayload {
  if (!value || typeof value !== "object") {
    return false;
  }
  const obj = value as Record<string, unknown>;
  return (
    obj.v === 1 &&
    obj.alg === ALGORITHM &&
    typeof obj.iv === "string" &&
    typeof obj.tag === "string" &&
    typeof obj.ct === "string"
  );
}

/** Clear the cached key (useful for tests). */
export function clearEncryptionKeyCache(): void {
  cachedEncryptionKey = null;
}
